#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"

namespace upx_killer::engine::application::elf_capture {
ElfCaptureResult ElfRuntimeCaptureUseCase::Execute(
    ElfCaptureRequest const& request,
    std::stop_token stopToken) const noexcept {
  auto result = capture_.Capture(request, stopToken);
  if (!result.image) return result;
  auto const& layout = result.image->layout;
  auto const expected = layout.imageType == elf::ElfImageType::Executable
                            ? layout.entryPoint
                            : result.image->loadBias.value + layout.entryPoint;
  if (result.resolvedEntryPoint != expected) {
    return {std::nullopt, result.resolvedEntryPoint,
            {contracts::JobOutcome::Failed,
             contracts::ErrorCategory::Execution,
             "elf.oep.mismatch", std::nullopt, 0}};
  }
  return result;
}
}  // namespace upx_killer::engine::application::elf_capture
