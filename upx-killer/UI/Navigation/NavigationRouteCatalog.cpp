#include "pch.h"
#include "UI/Navigation/NavigationRouteCatalog.h"

#include "UI/ViewModels/ConfigurationViewModel.h"
#include "UI/ViewModels/OverviewViewModel.h"

#include <stdexcept>
#include <utility>

#include <winrt/Windows.UI.Xaml.Interop.h>

namespace upx_killer::ui {
std::vector<NavigationRouteRegistration> NavigationRouteCatalog::Create(
    NavigationRouteDependencies dependencies) {
  if (!dependencies.picker || !dependencies.engineClient ||
      !dependencies.workspace || !dependencies.artifactExporter ||
      !dependencies.settingsStore || !dependencies.folderPicker) {
    throw std::invalid_argument("dependencies");
  }
  auto overview = [windowId = dependencies.windowId,
                   picker = dependencies.picker,
                   engineClient = dependencies.engineClient,
                   workspace = dependencies.workspace,
                   artifactExporter = dependencies.artifactExporter,
                   settingsStore = dependencies.settingsStore](auto const& frame) {
    auto viewModel =
        winrt::make<winrt::upx_killer::implementation::OverviewViewModel>();
    winrt::get_self<winrt::upx_killer::implementation::OverviewViewModel>(
        viewModel)
        ->Initialize(windowId, picker, engineClient, workspace,
                     artifactExporter, settingsStore);
    return frame.Navigate(
        winrt::xaml_typename<winrt::upx_killer::OverviewPage>(), viewModel);
  };
  auto configuration = [ownerWindowHandle = dependencies.ownerWindowHandle,
                        settingsStore = dependencies.settingsStore,
                        folderPicker = dependencies.folderPicker](auto const& frame) {
    auto viewModel = winrt::make<
        winrt::upx_killer::implementation::ConfigurationViewModel>();
    winrt::get_self<winrt::upx_killer::implementation::ConfigurationViewModel>(
        viewModel)
        ->Initialize(ownerWindowHandle, settingsStore, folderPicker);
    return frame.Navigate(
        winrt::xaml_typename<winrt::upx_killer::ConfigurationPage>(),
        viewModel);
  };
  return {{L"overview", std::move(overview)},
          {L"configuration", std::move(configuration)}};
}
}
