#include "pch.h"
#include "Application/Runtime/WslRuntimeSettingsWorkflow.h"

namespace upx_killer::application {
WslRuntimeSettings WslRuntimeSettingsWorkflow::Load() const noexcept {
  return store_ ? store_->Load() : WslRuntimeSettings{};
}

std::vector<WslDistributionInfo>
WslRuntimeSettingsWorkflow::Refresh() const noexcept {
  return catalog_ ? catalog_->List() : std::vector<WslDistributionInfo>{};
}

bool WslRuntimeSettingsWorkflow::Select(
    std::wstring distribution) const noexcept {
  if (!store_) return false;
  return store_->Save({std::move(distribution)});
}
}  // namespace upx_killer::application
