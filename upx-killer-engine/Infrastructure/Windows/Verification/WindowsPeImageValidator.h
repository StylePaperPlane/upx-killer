#pragma once

#include "Application/Artifacts/ArtifactPublicationUseCase.h"

namespace upx_killer::engine::verification {
class WindowsPeImageValidator final
    : public application::artifacts::IRepairedImageValidator {
 public:
  [[nodiscard]] application::artifacts::RepairedImageValidationResult Validate(
      application::artifacts::RepairedImageValidationRequest const& request)
      const noexcept override;
};
}
