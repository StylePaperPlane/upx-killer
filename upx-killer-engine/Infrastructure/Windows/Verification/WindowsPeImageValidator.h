#pragma once

#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Infrastructure/Windows/Loading/DllLoaderCatalog.h"

namespace upx_killer::engine::verification {
class WindowsPeImageValidator final
    : public application::artifacts::IArtifactValidator {
 public:
  explicit WindowsPeImageValidator(loading::DllLoaderCatalog const& loaders)
      : loaders_(loaders) {}

  [[nodiscard]] application::artifacts::ArtifactValidationResult Validate(
      application::artifacts::ArtifactValidationRequest const& request)
      const noexcept override;

 private:
  loading::DllLoaderCatalog const& loaders_;
};
}
