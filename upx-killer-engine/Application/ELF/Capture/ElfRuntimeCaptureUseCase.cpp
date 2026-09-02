#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"

namespace upx_killer::engine::application::elf_capture {
ElfCaptureResult ElfRuntimeCaptureUseCase::Execute(
    ElfCaptureRequest const& request,
    std::stop_token stopToken) const noexcept {
  auto result = capture_.Capture(request, stopToken);
  if (!result.image) return result;
  auto const& layout = result.image->layout;
  auto const expected =
      layout.imageType == elf::ElfImageType::Executable
          ? layout.entryPoint
          : layout.imageType == elf::ElfImageType::PositionIndependentExecutable
                ? result.image->loadBias.value + layout.entryPoint
                : 0;
  if (result.resolvedEntryPoint != expected) {
    return {std::nullopt, result.resolvedEntryPoint,
            ElfCaptureError::EntryPointMismatch, "elf.oep.mismatch"};
  }
  return result;
}
}  // namespace upx_killer::engine::application::elf_capture
