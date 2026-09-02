#include "Infrastructure/Linux/Debugging/ElfSnapshotCaptureRouter.h"

namespace upx_killer::elf_host::debugging {
engine::application::elf_capture::ElfCaptureResult
ElfSnapshotCaptureRouter::Capture(
    engine::application::elf_capture::ElfCaptureRequest const& request,
    std::stop_token stopToken) const noexcept {
  auto const& capture =
      request.target.packedLayout.imageType == engine::elf::ElfImageType::SharedObject
          ? sharedObject_
          : executable_;
  return capture.Capture(request, stopToken);
}
}  // namespace upx_killer::elf_host::debugging
