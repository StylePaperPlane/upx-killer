#pragma once

#include "Application/PE/Capabilities/PeBackendCapabilities.h"
#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Application/Backends/IUnpackBackend.h"

namespace upx_killer::engine::application::pe_preparation {
class PeTargetProbe final {
 public:
  PeTargetProbe(ITargetSourceReader const& sourceReader,
                PeBackendCapabilities const& capabilities)
      : sourceReader_(sourceReader), capabilities_(capabilities) {}

  [[nodiscard]] contracts::BackendProbeResult Execute(
      contracts::UnpackJobRequest const& request) const noexcept;

 private:
  ITargetSourceReader const& sourceReader_;
  PeBackendCapabilities const& capabilities_;
};
}
