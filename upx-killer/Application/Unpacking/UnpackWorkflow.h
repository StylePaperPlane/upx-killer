#pragma once

#include "Application/Unpacking/IUnpackEngineClient.h"
#include "Application/TemporaryFiles/ITemporaryArtifactWorkspace.h"

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::application {
class UnpackWorkflow final {
 public:
  UnpackWorkflow(std::shared_ptr<IUnpackEngineClient> client,
                 std::shared_ptr<ITemporaryArtifactWorkspace> workspace);
  [[nodiscard]] bool RefreshCapabilities() noexcept;
  [[nodiscard]] bool CapabilitiesLoaded() const noexcept;
  [[nodiscard]] bool HasCapabilities() const noexcept;
  [[nodiscard]] bool Supports(contracts::TargetDescriptor const& target) const noexcept;
  [[nodiscard]] contracts::JobResult Start(
      std::filesystem::path const& targetPath,
      contracts::TargetDescriptor const& target,
      std::optional<contracts::EntryPointHint> entryPoint = std::nullopt,
      IUnpackEngineClient::ProgressCallback const& progress = {}) const noexcept;

 private:
  std::shared_ptr<IUnpackEngineClient> m_client;
  std::shared_ptr<ITemporaryArtifactWorkspace> m_workspace;
  mutable std::mutex m_capabilitiesMutex;
  std::vector<contracts::BackendManifest> m_manifests;
  bool m_capabilitiesLoaded{};
};
}
