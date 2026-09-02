#pragma once

#include "Application/Runtime/WslRuntimeSettings.h"
#include "Application/TemporaryFiles/ITemporaryFolderPicker.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"
#include "UI/Navigation/NavigationRouter.h"

#include <cstdint>
#include <memory>

namespace upx_killer::ui::composition {

struct ConfigurationRouteDependencies {
  std::uintptr_t ownerWindowHandle{};
  std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore;
  std::shared_ptr<application::ITemporaryFolderPicker> folderPicker;
  std::shared_ptr<application::IWslRuntimeSettingsStore> wslSettingsStore;
  std::shared_ptr<application::IWslDistributionCatalog> wslDistributionCatalog;
};

class ConfigurationRouteFactory final {
 public:
  [[nodiscard]] static NavigationRouteRegistration Create(
      ConfigurationRouteDependencies dependencies);
};

}  // namespace upx_killer::ui::composition
