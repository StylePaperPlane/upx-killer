#pragma once

#include "Application/Backends/IUnpackBackend.h"
#include "Core/Jobs/UnpackJob.h"
#include "Core/Targets/TargetDescriptor.h"

#include <filesystem>
#include <functional>
#include <span>

namespace upx_killer::engine::application::artifacts {

struct PublishArtifactRequest {
  std::filesystem::path outputPath;
  std::span<std::byte const> bytes;
  contracts::TargetDescriptor target;
  std::filesystem::path dependencyDirectory;
  std::uint32_t timeoutMilliseconds{};
  bool retainFailedOutput{};
};

class IArtifactPublisher {
 public:
  virtual ~IArtifactPublisher() = default;
  [[nodiscard]] virtual contracts::JobResult Publish(
      PublishArtifactRequest const& request,
      contracts::ProgressCallback const& progress) const noexcept = 0;
};

}  // namespace upx_killer::engine::application::artifacts
