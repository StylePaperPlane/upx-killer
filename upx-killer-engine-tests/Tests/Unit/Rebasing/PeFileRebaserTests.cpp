#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Application/PE/Preparation/PeExecutionPlanFactory.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Core/PE/Parsing/PeParser.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

class RecordingSnapshotCapture final : public application::pe_capture::IPeSnapshotCapture {
 public:
  application::pe_capture::PeSnapshotCaptureResult CaptureOne(
      application::pe_capture::PeSnapshotCaptureRequest const& request,
      std::function<void(EngineStage)> const&, std::stop_token) const noexcept override {
    bases.push_back(request.requiredBase.value);
    application::pe_capture::PeCapturedRun run{};
    run.image.loadedAddress = {request.requiredBase.value};
    run.entryPoint = {0x1000};
    return {std::move(run), application::pe_capture::PeSnapshotCaptureError::None};
  }

  mutable std::vector<std::uint64_t> bases;
};

std::vector<std::byte> MakeRelocatablePe() {
  std::vector<std::byte> bytes(0x600);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  nt->FileHeader.NumberOfSections = 2;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt->OptionalHeader.ImageBase = 0x140000000ull;
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x3000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  nt->OptionalHeader.DllCharacteristics =
      IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
  nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = {0x2000, 12};

  auto* sections = IMAGE_FIRST_SECTION(nt);
  std::memcpy(sections[0].Name, ".text", 5);
  sections[0].Misc.VirtualSize = 0x200;
  sections[0].VirtualAddress = 0x1000;
  sections[0].SizeOfRawData = 0x200;
  sections[0].PointerToRawData = 0x200;
  sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  std::memcpy(sections[1].Name, ".reloc", 6);
  sections[1].Misc.VirtualSize = 0x200;
  sections[1].VirtualAddress = 0x2000;
  sections[1].SizeOfRawData = 0x200;
  sections[1].PointerToRawData = 0x400;
  sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

  auto value = 0x140001100ull;
  std::memcpy(bytes.data() + 0x220, &value, sizeof(value));
  IMAGE_BASE_RELOCATION block{0x1000, 12};
  std::memcpy(bytes.data() + 0x400, &block, sizeof(block));
  auto entries = reinterpret_cast<WORD*>(bytes.data() + 0x408);
  entries[0] = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | 0x20);
  entries[1] = 0;
  return bytes;
}
}

int RunPeFileRebaserTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  auto source = MakeRelocatablePe();
  auto parsed = pe::PeParser::Parse(source);
  expect(parsed.Succeeded(), "rebasing fixture parses");
  if (!parsed.layout) return failures;

  auto rebased =
      pe::rebasing::PeFileRebaser::Rebase(source, *parsed.layout, LoadedAddress{0x180000000ull});
  expect(rebased.Succeeded(), "packed target is rebased through its source relocation table");
  if (rebased.image) {
    auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS64 const*>(rebased.image->bytes.data() +
                                                                 parsed.layout->ntHeaderOffset);
    std::uint64_t relocated{};
    std::memcpy(&relocated, rebased.image->bytes.data() + 0x220, sizeof(relocated));
    expect(nt->OptionalHeader.ImageBase == 0x180000000ull,
           "rebased file records the required base");
    expect(relocated == 0x180001100ull, "DIR64 source slot receives the exact base delta");
    expect(
        (nt->OptionalHeader.DllCharacteristics &
         (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA)) == 0,
        "controlled-base staging disables ASLR");
    expect(rebased.image->sourceSlots.size() == 1 &&
               rebased.image->sourceSlots[0].location.value == 0x1020 &&
               rebased.image->sourceSlots[0].imageTarget &&
               rebased.image->sourceSlots[0].imageTarget->value == 0x1100,
           "source relocation evidence is preserved for stub-residue filtering");
  }

  application::PeBackendCapabilities capabilities{{
      {upx_killer::contracts::BinaryFamily::Pe,
       upx_killer::contracts::BinaryClass::Bits64,
       upx_killer::contracts::CpuArchitecture::X64,
       upx_killer::contracts::ImageKind::Executable},
  }};
  auto relocatablePlan = application::pe_preparation::PeExecutionPlanFactory::Create(
      *parsed.layout, capabilities);
  expect(parsed.layout->sourceLoadPolicy.hasRelocations && relocatablePlan &&
             relocatablePlan->captureCount == 3 && relocatablePlan->rebuildRelocations,
         "unstripped source relocation directory keeps three controlled captures");

  auto stripped = source;
  auto* strippedNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(stripped.data() + 0x80);
  strippedNt->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
  auto strippedLayout = pe::PeParser::Parse(stripped);
  expect(strippedLayout.layout && !strippedLayout.layout->sourceLoadPolicy.hasRelocations,
         "stripped PE64 with a shell relocation directory is fixed-base");
  if (strippedLayout.layout) {
    auto fixedPlan = application::pe_preparation::PeExecutionPlanFactory::Create(
        *strippedLayout.layout, capabilities);
    expect(fixedPlan && !fixedPlan->rebuildRelocations && fixedPlan->captureCount == 1 &&
               fixedPlan->captureBases[0].value == strippedLayout.layout->preferredImageBase,
           "stripped PE64 requests only its preferred base");
    if (fixedPlan) {
      application::pe_preparation::PreparedPeTarget target{};
      target.sourceBytes = stripped;
      target.layout = *strippedLayout.layout;
      target.entryPointTarget = RelativeVirtualAddress{0x1000};
      target.executionPlan = *fixedPlan;
      target.hasSourceRelocationDirectory = true;
      RecordingSnapshotCapture snapshot;
      application::pe_capture::PeRuntimeCaptureUseCase capture{snapshot};
      UnpackRequest request{};
      auto result = capture.Execute(request, target);
      expect(result.Succeeded() && snapshot.bases.size() == 1 &&
                 snapshot.bases.front() == strippedLayout.layout->preferredImageBase,
             "fixed source with a shell relocation directory captures once");
    }
    auto staged = pe::rebasing::PeFileRebaser::Rebase(
        stripped, *strippedLayout.layout,
        LoadedAddress{strippedLayout.layout->preferredImageBase});
    expect(staged.Succeeded() && staged.image && staged.image->sourceSlots.size() == 1,
           "shell relocation entries remain validated at the preferred base");
  }

  auto malformed = source;
  auto* entries = reinterpret_cast<WORD*>(malformed.data() + 0x408);
  entries[0] = static_cast<WORD>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x20);
  auto malformedLayout = pe::PeParser::Parse(malformed);
  auto rejected = pe::rebasing::PeFileRebaser::Rebase(malformed, *malformedLayout.layout,
                                                      LoadedAddress{0x180000000ull});
  expect(rejected.error == pe::rebasing::PeFileRebaseError::UnsupportedRelocationType,
         "non-DIR64 source relocations are rejected");
  if (strippedLayout.layout) {
    auto malformedStripped = stripped;
    auto* malformedEntries = reinterpret_cast<WORD*>(malformedStripped.data() + 0x408);
    malformedEntries[0] = static_cast<WORD>((IMAGE_REL_BASED_HIGHLOW << 12) | 0x20);
    auto malformedStrippedLayout = pe::PeParser::Parse(malformedStripped);
    auto rejectedFixed = pe::rebasing::PeFileRebaser::Rebase(
        malformedStripped, *malformedStrippedLayout.layout,
        LoadedAddress{strippedLayout.layout->preferredImageBase});
    expect(rejectedFixed.error == pe::rebasing::PeFileRebaseError::UnsupportedRelocationType,
           "fixed-base staging rejects malformed shell relocation entries");
  }
  return failures;
}
