#pragma once

#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Application/Backends/IUnpackBackend.h"

namespace upx_killer::engine::application::pe_preparation {
class PeTargetProbe final {
 public:
  explicit PeTargetProbe(ITargetSourceReader const& sourceReader)
      : sourceReader_(sourceReader) {}

  [[nodiscard]] contracts::BackendProbeResult Execute(
      contracts::UnpackJobRequest const& request) const noexcept;

 private:
  ITargetSourceReader const& sourceReader_;
};
}
