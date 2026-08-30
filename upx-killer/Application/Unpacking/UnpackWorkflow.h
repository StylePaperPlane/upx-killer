#pragma once

#include "Application/Unpacking/IUnpackEngineClient.h"

#include <filesystem>
#include <memory>
#include <optional>
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
  [[nodiscard]] UnpackResult Start(
      std::filesystem::path const& targetPath,
      std::optional<engine::RelativeVirtualAddress> oep = std::nullopt,
      IUnpackEngineClient::ProgressCallback const& progress = {}) const noexcept;

 private:
  std::shared_ptr<IUnpackEngineClient> m_client;
};
}
