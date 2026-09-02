#pragma once

#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"

namespace upx_killer::elf_host::debugging {

class ElfSnapshotCaptureRouter final
    : public engine::application::elf_capture::IElfSnapshotCapture {
 public:
  ElfSnapshotCaptureRouter(
      engine::application::elf_capture::IElfSnapshotCapture const& executable,
      engine::application::elf_capture::IElfSnapshotCapture const& sharedObject)
      : executable_(executable), sharedObject_(sharedObject) {}

  [[nodiscard]] engine::application::elf_capture::ElfCaptureResult Capture(
      engine::application::elf_capture::ElfCaptureRequest const& request,
      std::stop_token stopToken) const noexcept override;

 private:
  engine::application::elf_capture::IElfSnapshotCapture const& executable_;
  engine::application::elf_capture::IElfSnapshotCapture const& sharedObject_;
};

}  // namespace upx_killer::elf_host::debugging
