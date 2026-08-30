#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"
#include "Core/PE/Parsing/PeParser.h"

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <vector>

namespace {
using namespace upx_killer::engine;

void Expect(bool value, char const* message, int& failures) {
  if (value) return;
  std::cerr << "FAIL: " << message << '\n';
  ++failures;
}

std::filesystem::path FixturePath() {
  wchar_t executable[MAX_PATH]{};
  GetModuleFileNameW(nullptr, executable, MAX_PATH);
  return std::filesystem::path{executable}.parent_path() /
         L"upx-killer-engine-fixture.exe";
}

std::vector<std::byte> ReadFixture() {
  std::ifstream stream(FixturePath(), std::ios::binary | std::ios::ate);
  if (!stream) return {};
  std::vector<std::byte> bytes(static_cast<std::size_t>(stream.tellg()));
  stream.seekg(0);
  stream.read(reinterpret_cast<char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  return bytes;
}

class MemorySourceReader final
    : public application::pe_preparation::ITargetSourceReader {
 public:
  explicit MemorySourceReader(std::vector<std::byte> bytes)
      : bytes_(std::move(bytes)) {}

  application::pe_preparation::TargetSourceReadResult Read(
      std::filesystem::path const&, std::uint64_t maximumSize) const noexcept override {
    if (bytes_.size() > maximumSize) return {};
    return {application::pe_preparation::TargetSource{bytes_, FixturePath().parent_path()}, 0};
  }

 private:
  std::vector<std::byte> bytes_;
};

class TimedOutSnapshotCapture final
    : public application::pe_capture::IPeSnapshotCapture {
 public:
  application::pe_capture::PeSnapshotCaptureResult CaptureOne(
      application::pe_capture::PeSnapshotCaptureRequest const&,
      std::function<void(EngineStage)> const&,
      std::stop_token) const noexcept override {
    ++calls;
    return {std::nullopt, EngineOutcome::TimedOut, EngineError::TimedOut, WAIT_TIMEOUT};
  }

  mutable unsigned calls{};
};

class MemoryArtifactStore final
    : public application::artifacts::IArtifactStore {
 public:
  application::artifacts::ArtifactStageResult Stage(
      std::filesystem::path const&, std::span<std::byte const> bytes) const noexcept override {
    staged.assign(bytes.begin(), bytes.end());
    return {std::filesystem::path{L"staged-image.exe"}, 0};
  }
  std::uint32_t Promote(std::filesystem::path const&,
                        std::filesystem::path const&) const noexcept override {
    promoted = true;
    return 0;
  }
  void Remove(std::filesystem::path const&) const noexcept override { removed = true; }

  mutable std::vector<std::byte> staged;
  mutable bool promoted{};
  mutable bool removed{};
};

class AcceptingValidator final
    : public application::artifacts::IArtifactValidator {
 public:
  application::artifacts::ArtifactValidationResult Validate(
      application::artifacts::ArtifactValidationRequest const&) const noexcept override {
    return {true, true, true, false, 0, 0};
  }
};

class RejectingValidator final
    : public application::artifacts::IArtifactValidator {
 public:
  application::artifacts::ArtifactValidationResult Validate(
      application::artifacts::ArtifactValidationRequest const&) const noexcept override {
    return {true, true, true, false, ERROR_BAD_EXE_FORMAT, 0};
  }
};
}

int RunPeUseCaseTests() {
  int failures{};
  auto bytes = ReadFixture();
  Expect(!bytes.empty(), "use-case fixture can be read", failures);
  auto parsed = pe::PeParser::Parse(bytes);
  Expect(parsed.layout.has_value(), "use-case fixture is a valid PE", failures);
  if (!parsed.layout) return failures + 1;

  MemorySourceReader source{bytes};
  application::PeBackendCapabilities capabilities{{
      {upx_killer::contracts::BinaryFamily::Pe,
       upx_killer::contracts::BinaryClass::Bits64,
       upx_killer::contracts::CpuArchitecture::X64,
       upx_killer::contracts::ImageKind::Executable},
  }};
  application::pe_preparation::PeTargetPreparationUseCase preparation{
      source, capabilities};
  UnpackRequest request{};
  request.targetPath = FixturePath();
  request.outputPath = L"fixture.use-case.dumped.exe";
  request.oep = parsed.layout->entryPoint;
  auto prepared = preparation.Execute(request);
  Expect(prepared.Succeeded(), "preparation use case returns a prepared target", failures);
  if (!prepared.target) return failures + 1;

  TimedOutSnapshotCapture snapshot;
  application::pe_capture::PeRuntimeCaptureUseCase capture{snapshot};
  auto captureResult = capture.Execute(request, *prepared.target);
  Expect(!captureResult.Succeeded() && captureResult.outcome == EngineOutcome::TimedOut &&
             captureResult.error == EngineError::TimedOut && snapshot.calls == 1,
         "capture use case propagates a single-capture timeout", failures);

  application::pe_reconstruction::PeImageReconstructionUseCase reconstruction;
  auto reconstructionResult = reconstruction.Execute(
      request, *prepared.target, application::pe_capture::PeCaptureEvidence{});
  Expect(!reconstructionResult.Succeeded(),
         "reconstruction use case rejects missing capture evidence", failures);

  MemoryArtifactStore store;
  AcceptingValidator validator;
  application::artifacts::ArtifactPublicationUseCase publication{store, validator};
  pe::FixedPeImage fixed{};
  fixed.bytes = {std::byte{0x4d}, std::byte{0x5a}};
  fixed.quality = ArtifactQuality::Complete;
  auto publicationResult = publication.Execute(
      {request.outputPath, std::move(fixed.bytes),
      {upx_killer::contracts::BinaryFamily::Pe,
       upx_killer::contracts::BinaryClass::Bits64,
       upx_killer::contracts::CpuArchitecture::X64,
       upx_killer::contracts::ImageKind::Executable},
       prepared.target->dependencyDirectory, 3000, fixed.quality,
       std::move(fixed.warnings), request.retainFailedOutput});
  Expect(publicationResult.Succeeded() &&
             publicationResult.outcome == EngineOutcome::Completed &&
             store.promoted && !store.removed,
         "publication use case stages, validates, and promotes an artifact", failures);

  MemoryArtifactStore rejectedStore;
  RejectingValidator rejectingValidator;
  application::artifacts::ArtifactPublicationUseCase rejectedPublication{
      rejectedStore, rejectingValidator};
  auto rejected = rejectedPublication.Execute(
      {request.outputPath, {std::byte{0x4d}, std::byte{0x5a}},
       {upx_killer::contracts::BinaryFamily::Elf,
        upx_killer::contracts::BinaryClass::Bits64,
        upx_killer::contracts::CpuArchitecture::X64,
        upx_killer::contracts::ImageKind::Executable},
       {}, 3000, ArtifactQuality::Complete, {}, false});
  Expect(!rejected.Succeeded() && rejectedStore.removed &&
             !rejectedStore.promoted,
         "publication removes a failed staged artifact regardless of format",
         failures);

  MemoryArtifactStore retainedStore;
  application::artifacts::ArtifactPublicationUseCase retainedPublication{
      retainedStore, rejectingValidator};
  auto retained = retainedPublication.Execute(
      {request.outputPath, {std::byte{0x7f}, std::byte{0x45}},
       {upx_killer::contracts::BinaryFamily::Elf,
        upx_killer::contracts::BinaryClass::Bits32,
        upx_killer::contracts::CpuArchitecture::X86,
        upx_killer::contracts::ImageKind::SharedLibrary},
       {}, 3000, ArtifactQuality::Partial, {}, true});
  Expect(!retained.Succeeded() && !retainedStore.removed &&
             !retainedStore.promoted,
         "publication retains an explicitly requested failed diagnostic artifact",
         failures);
  return failures;
}
