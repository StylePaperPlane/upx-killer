#pragma once

#include "Application/Runtime/WslRuntimeSettings.h"

namespace upx_killer::infrastructure {

class WslDistributionCatalog final
    : public application::IWslDistributionCatalog {
 public:
  [[nodiscard]] std::vector<application::WslDistributionInfo> List()
      const noexcept override;
};

}  // namespace upx_killer::infrastructure
