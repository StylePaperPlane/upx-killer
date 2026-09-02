#pragma once

#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"
#include "Infrastructure/Linux/Loading/ElfSharedObjectLoaderCatalog.h"

namespace upx_killer::elf_host::debugging {

class PtraceElfSharedObjectSnapshotCapture final
    : public engine::application::elf_capture::IElfSnapshotCapture {
 public:
  explicit PtraceElfSharedObjectSnapshotCapture(
      loading::ElfSharedObjectLoaderCatalog const& loaders)
      : loaders_(loaders) {}

  [[nodiscard]] engine::application::elf_capture::ElfCaptureResult Capture(
      engine::application::elf_capture::ElfCaptureRequest const& request,
      std::stop_token stopToken) const noexcept override;

 private:
  loading::ElfSharedObjectLoaderCatalog const& loaders_;
};

}  // namespace upx_killer::elf_host::debugging
