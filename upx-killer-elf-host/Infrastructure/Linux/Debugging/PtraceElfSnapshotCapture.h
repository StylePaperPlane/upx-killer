#pragma once

#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"

namespace upx_killer::elf_host::debugging {

class PtraceElfSnapshotCapture final
    : public engine::application::elf_capture::IElfSnapshotCapture {
 public:
  [[nodiscard]] engine::application::elf_capture::ElfCaptureResult Capture(
      engine::application::elf_capture::ElfCaptureRequest const& request,
      std::stop_token stopToken) const noexcept override;
};

}  // namespace upx_killer::elf_host::debugging
