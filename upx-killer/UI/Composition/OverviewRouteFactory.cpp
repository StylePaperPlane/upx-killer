#include "pch.h"
#include "UI/Composition/OverviewRouteFactory.h"

#include "Application/Unpacking/UnpackWorkflow.h"
#include "UI/ViewModels/OverviewViewModel.h"

#include <stdexcept>
#include <utility>

#include <winrt/Windows.UI.Xaml.Interop.h>

namespace upx_killer::ui::composition {
NavigationRouteRegistration OverviewRouteFactory::Create(
    OverviewRouteDependencies dependencies) {
  if (!dependencies.picker || !dependencies.engineClient ||
      !dependencies.workspace || !dependencies.artifactExporter ||
      !dependencies.settingsStore)
    throw std::invalid_argument("dependencies");
  return {
      L"overview",
      [windowId = dependencies.windowId, picker = std::move(dependencies.picker),
       engineClient = std::move(dependencies.engineClient),
       workspace = std::move(dependencies.workspace),
       artifactExporter = std::move(dependencies.artifactExporter),
       settingsStore = std::move(dependencies.settingsStore)](auto const& frame) {
        auto viewModel =
            winrt::make<winrt::upx_killer::implementation::OverviewViewModel>();
        winrt::get_self<winrt::upx_killer::implementation::OverviewViewModel>(
            viewModel)
            ->Initialize(
                windowId,
                std::make_unique<application::TargetSelectionWorkflow>(picker),
                std::make_unique<application::UnpackWorkflow>(engineClient,
                                                               workspace),
                artifactExporter, settingsStore);
        return frame.Navigate(
            winrt::xaml_typename<winrt::upx_killer::OverviewPage>(), viewModel);
      }};
}
}  // namespace upx_killer::ui::composition
