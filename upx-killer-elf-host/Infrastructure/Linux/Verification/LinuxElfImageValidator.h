#pragma once

#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Infrastructure/Linux/Loading/IsolatedElfLoadVerifier.h"

#include <cstdint>
#include <filesystem>

namespace upx_killer::elf_host::verification {

class LinuxElfImageValidator final
    : public engine::application::artifacts::IArtifactValidator {
 public:
  explicit LinuxElfImageValidator(
      loading::IsolatedElfLoadVerifier const& loaderVerifier)
      : loaderVerifier_(loaderVerifier) {}

  [[nodiscard]] engine::application::artifacts::ArtifactValidationResult
  Validate(engine::application::artifacts::ArtifactValidationRequest const&
               request) const noexcept override;

 private:
  loading::IsolatedElfLoadVerifier const& loaderVerifier_;
};

}  // namespace upx_killer::elf_host::verification
