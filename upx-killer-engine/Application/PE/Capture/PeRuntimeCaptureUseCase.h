#pragma once

#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/Imports/ImportTypes.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"

#include <chrono>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <vector>

namespace upx_killer::engine::application::pe_capture {
struct PeCapturedRun {
  dumping::DumpedImage image;
  RelativeVirtualAddress entryPoint;
  pe::imports::RuntimeModuleSnapshot runtimeImports;
};

struct PeSnapshotCaptureRequest {
  std::filesystem::path targetPath;
  std::filesystem::path dependencyDirectory;
  pe::PeFormat format{pe::PeFormat::Pe64};
  pe::PeImageKind imageKind{pe::PeImageKind::Executable};
  std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> entryPointTarget;
  pe::PeImageLayout const* layout{};
  std::span<std::byte const> stagedImage;
  LoadedAddress requiredBase;
  std::chrono::milliseconds timeout{60'000};
  std::uint64_t maximumImageSize{1ull << 30};
  bool collectRuntimeImports{};
};

struct PeSnapshotCaptureResult {
  std::optional<PeCapturedRun> capture;
  EngineOutcome outcome{EngineOutcome::Failed};
  EngineError error{EngineError::None};
  std::uint32_t nativeError{};
};

class IPeSnapshotCapture {
 public:
  virtual ~IPeSnapshotCapture() = default;
  [[nodiscard]] virtual PeSnapshotCaptureResult CaptureOne(
      PeSnapshotCaptureRequest const& request,
      std::function<void(EngineStage)> const& progress,
      std::stop_token stopToken) const noexcept = 0;
};

struct PeCaptureEvidence {
  std::vector<PeCapturedRun> runs;
  std::vector<pe::rebasing::SourceRelocationSlot> sourceRelocationSlots;
};

struct PeRuntimeCaptureResult {
  std::optional<PeCaptureEvidence> evidence;
  EngineOutcome outcome{EngineOutcome::Failed};
  EngineError error{EngineError::None};
  std::uint32_t nativeError{};

  [[nodiscard]] bool Succeeded() const noexcept { return evidence.has_value(); }
};

class PeRuntimeCaptureUseCase final {
 public:
  explicit PeRuntimeCaptureUseCase(IPeSnapshotCapture const& snapshotCapture)
      : snapshotCapture_(snapshotCapture) {}

  [[nodiscard]] PeRuntimeCaptureResult Execute(
      UnpackRequest const& request,
      pe_preparation::PreparedPeTarget const& target,
      std::function<void(EngineStage)> const& progress = {},
      std::stop_token stopToken = {}) const noexcept;

 private:
  IPeSnapshotCapture const& snapshotCapture_;
};
}
