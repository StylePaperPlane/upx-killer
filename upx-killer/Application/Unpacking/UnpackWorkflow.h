#pragma once

#include "Application/Unpacking/IUnpackEngineClient.h"

#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::application {
enum class UnpackOutcome {
  NeedsOep,
  Partial,
  Succeeded,
  Unsupported,
  UnsupportedPacker,
  OepNotFound,
  ImportsNotFound,
  ImportsAmbiguous,
  RelocationEvidenceFailed,
  RelocationValidationFailed,
  Wow64Unavailable,
  UnsupportedPe32Relocation,
  Failed,
};

struct UnpackResult {
  UnpackOutcome outcome{UnpackOutcome::Failed};
  std::filesystem::path outputPath;
  std::vector<std::string> warnings;
};

class UnpackWorkflow final {
 public:
  explicit UnpackWorkflow(std::shared_ptr<IUnpackEngineClient> client);
  [[nodiscard]] bool RefreshCapabilities() noexcept;
  [[nodiscard]] bool CapabilitiesLoaded() const noexcept;
  [[nodiscard]] bool HasCapabilities() const noexcept;
  [[nodiscard]] bool Supports(contracts::TargetDescriptor const& target) const noexcept;
  [[nodiscard]] UnpackResult Start(
      std::filesystem::path const& targetPath,
      std::optional<contracts::EntryPointHint> entryPoint = std::nullopt,
      IUnpackEngineClient::ProgressCallback const& progress = {}) const noexcept;

 private:
  std::shared_ptr<IUnpackEngineClient> m_client;
  mutable std::mutex m_capabilitiesMutex;
  std::vector<contracts::BackendManifest> m_manifests;
  bool m_capabilitiesLoaded{};
};
}
