#pragma once

#include "Application/Unpacking/IUnpackEngineClient.h"
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>

namespace upx_killer::infrastructure {
class EngineHostClient final : public application::IUnpackEngineClient {
 public:
  explicit EngineHostClient(std::filesystem::path hostPath);
  [[nodiscard]] static std::filesystem::path AdjacentHostPath();
  [[nodiscard]] std::vector<contracts::BackendManifest> QueryCapabilities() noexcept override;
  [[nodiscard]] contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      ProgressCallback const& progress = {}) noexcept override;

 private:
  std::filesystem::path m_hostPath;
  std::mutex m_capabilitiesMutex;
  std::optional<std::vector<contracts::BackendManifest>> m_capabilities;
};
}
