#pragma once

#include "Application/Artifacts/IArtifactPublisher.h"
#include "Infrastructure/Linux/Verification/LinuxElfImageValidator.h"

namespace upx_killer::elf_host::storage {

class LinuxArtifactPublisher final
    : public engine::application::artifacts::IArtifactPublisher {
 public:
  explicit LinuxArtifactPublisher(
      verification::LinuxElfImageValidator const& validator)
      : validator_(validator) {}

  [[nodiscard]] contracts::JobResult Publish(
      engine::application::artifacts::PublishArtifactRequest const& request,
      contracts::ProgressCallback const& progress) const noexcept override;

 private:
  verification::LinuxElfImageValidator const& validator_;
};

}  // namespace upx_killer::elf_host::storage
