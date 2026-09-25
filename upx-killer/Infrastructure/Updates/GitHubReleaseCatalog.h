#pragma once

#include "Application/Updates/UpdateCheckWorkflow.h"

namespace upx_killer::infrastructure {

class GitHubReleaseCatalog final : public application::IReleaseCatalog {
 public:
  [[nodiscard]] std::optional<std::string> LatestStableVersion()
      const noexcept override;
};

}  // namespace upx_killer::infrastructure
