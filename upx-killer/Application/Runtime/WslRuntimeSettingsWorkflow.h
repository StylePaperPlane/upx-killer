#pragma once

#include "Application/Runtime/WslRuntimeSettings.h"

#include <memory>

namespace upx_killer::application {

class WslRuntimeSettingsWorkflow final {
 public:
  WslRuntimeSettingsWorkflow(
      std::shared_ptr<IWslRuntimeSettingsStore> store,
      std::shared_ptr<IWslDistributionCatalog> catalog)
      : store_(std::move(store)), catalog_(std::move(catalog)) {}

  [[nodiscard]] WslRuntimeSettings Load() const noexcept;
  [[nodiscard]] std::vector<WslDistributionInfo> Refresh() const noexcept;
  [[nodiscard]] bool Select(std::wstring distribution) const noexcept;

 private:
  std::shared_ptr<IWslRuntimeSettingsStore> store_;
  std::shared_ptr<IWslDistributionCatalog> catalog_;
};

}  // namespace upx_killer::application
