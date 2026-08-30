#pragma once

#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"

namespace upx_killer::engine::capture {
class WindowsPeSnapshotCapture final
    : public application::pe_capture::IPeSnapshotCapture {
 public:
  [[nodiscard]] application::pe_capture::PeSnapshotCaptureResult CaptureOne(
      application::pe_capture::PeSnapshotCaptureRequest const& request,
      std::function<void(EngineStage)> const& progress,
      std::stop_token stopToken) const noexcept override;
};
}
