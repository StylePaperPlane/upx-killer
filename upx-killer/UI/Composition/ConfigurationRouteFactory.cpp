#include "pch.h"
#include "UI/Composition/ConfigurationRouteFactory.h"

#include "Application/Runtime/WslRuntimeSettingsWorkflow.h"
#include "Application/TemporaryFiles/TemporaryFileSettingsWorkflow.h"
#include "UI/ViewModels/ConfigurationViewModel.h"

#include <stdexcept>
#include <utility>

#include <winrt/Windows.UI.Xaml.Interop.h>

namespace upx_killer::ui::composition {
NavigationRouteRegistration ConfigurationRouteFactory::Create(
    ConfigurationRouteDependencies dependencies) {
  if (!dependencies.settingsStore || !dependencies.folderPicker ||
      !dependencies.wslSettingsStore || !dependencies.wslDistributionCatalog)
    throw std::invalid_argument("dependencies");
  return {
      L"configuration",
      [ownerWindowHandle = dependencies.ownerWindowHandle,
       settingsStore = std::move(dependencies.settingsStore),
       folderPicker = std::move(dependencies.folderPicker),
       wslSettingsStore = std::move(dependencies.wslSettingsStore),
       wslDistributionCatalog = std::move(dependencies.wslDistributionCatalog)](
          auto const& frame) {
        auto viewModel = winrt::make<
            winrt::upx_killer::implementation::ConfigurationViewModel>();
        winrt::get_self<
            winrt::upx_killer::implementation::ConfigurationViewModel>(
            viewModel)
            ->Initialize(
                ownerWindowHandle,
                std::make_unique<application::TemporaryFileSettingsWorkflow>(
                    settingsStore, folderPicker),
                std::make_unique<application::WslRuntimeSettingsWorkflow>(
                    wslSettingsStore, wslDistributionCatalog));
        return frame.Navigate(
            winrt::xaml_typename<winrt::upx_killer::ConfigurationPage>(),
            viewModel);
      }};
}
}  // namespace upx_killer::ui::composition
