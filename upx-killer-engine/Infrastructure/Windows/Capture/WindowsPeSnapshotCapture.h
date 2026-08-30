#pragma once

#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Infrastructure/Windows/Loading/DllLoaderCatalog.h"

namespace upx_killer::engine::capture {
class WindowsPeSnapshotCapture final
    : public application::pe_capture::IPeSnapshotCapture {
 public:
  explicit WindowsPeSnapshotCapture(loading::DllLoaderCatalog const& loaders)
      : loaders_(loaders) {}

  [[nodiscard]] application::pe_capture::PeSnapshotCaptureResult CaptureOne(
      application::pe_capture::PeSnapshotCaptureRequest const& request,
      std::function<void(EngineStage)> const& progress,
      std::stop_token stopToken) const noexcept override;

 private:
  loading::DllLoaderCatalog const& loaders_;
};
}
