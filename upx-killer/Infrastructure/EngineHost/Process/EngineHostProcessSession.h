#pragma once

#include "Application/Backends/IUnpackBackend.h"

#include <filesystem>
#include <string>
#include <vector>

namespace upx_killer::infrastructure {
struct EngineHostCapabilityResult {
  bool succeeded{};
  std::vector<contracts::BackendManifest> manifests;
  std::string detailCode;
  std::uint32_t nativeCode{};
};

class EngineHostProcessSession final {
 public:
  [[nodiscard]] static EngineHostCapabilityResult QueryCapabilities(
      std::filesystem::path const& hostPath) noexcept;
  [[nodiscard]] static contracts::JobResult Execute(
      std::filesystem::path const& hostPath,
      contracts::UnpackJobRequest const& request,
      contracts::ProgressCallback const& progress = {}) noexcept;
};
}
