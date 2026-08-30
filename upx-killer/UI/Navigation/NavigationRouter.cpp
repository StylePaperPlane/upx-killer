#include "pch.h"
#include "UI/Navigation/NavigationRouter.h"

#include "UI/ViewModels/OverviewViewModel.h"
#include "UI/ViewModels/ConfigurationViewModel.h"

#include <stdexcept>
#include <utility>

#include <winrt/Windows.UI.Xaml.Interop.h>

namespace {
constexpr wchar_t OverviewRoute[] = L"overview";
constexpr wchar_t ConfigurationRoute[] = L"configuration";
}

namespace upx_killer::ui {
NavigationRouter::NavigationRouter(
    winrt::Microsoft::UI::Xaml::Controls::Frame const& frame,
    winrt::Microsoft::UI::WindowId const& windowId, std::uintptr_t ownerWindowHandle,
    std::shared_ptr<application::ITargetFilePicker> picker,
    std::shared_ptr<application::IUnpackEngineClient> engineClient,
    std::shared_ptr<application::IArtifactExporter> artifactExporter,
    std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore,
    std::shared_ptr<application::ITemporaryFolderPicker> folderPicker)
    : m_frame(frame),
      m_windowId(windowId),
      m_ownerWindowHandle(ownerWindowHandle),
      m_picker(std::move(picker)),
      m_engineClient(std::move(engineClient)),
      m_artifactExporter(std::move(artifactExporter)),
      m_settingsStore(std::move(settingsStore)),
      m_folderPicker(std::move(folderPicker)) {
  if (!m_frame) {
    throw std::invalid_argument("frame");
  }

  if (!m_picker) {
    throw std::invalid_argument("picker");
  }

  if (!m_engineClient) {
    throw std::invalid_argument("engineClient");
  }
  if (!m_artifactExporter) {
    throw std::invalid_argument("artifactExporter");
  }
  if (!m_settingsStore) {
    throw std::invalid_argument("settingsStore");
  }
  if (!m_folderPicker) {
    throw std::invalid_argument("folderPicker");
  }
}

bool NavigationRouter::Navigate(winrt::hstring const& routeTag) {
  if (routeTag == m_currentRoute && m_frame.Content()) {
    return true;
  }

  if (routeTag == OverviewRoute) {
    return NavigateToOverview();
  }
  if (routeTag == ConfigurationRoute) {
    return NavigateToConfiguration();
  }

  return false;
}

bool NavigationRouter::NavigateToOverview() {
  auto const viewModel = winrt::make<winrt::upx_killer::implementation::OverviewViewModel>();

  winrt::get_self<winrt::upx_killer::implementation::OverviewViewModel>(viewModel)->Initialize(
      m_windowId, m_picker, m_engineClient, m_artifactExporter, m_settingsStore);

  bool const navigated =
      m_frame.Navigate(winrt::xaml_typename<winrt::upx_killer::OverviewPage>(), viewModel);

  if (navigated) {
    m_currentRoute = OverviewRoute;
  }

  return navigated;
}

bool NavigationRouter::NavigateToConfiguration() {
  auto const viewModel = winrt::make<winrt::upx_killer::implementation::ConfigurationViewModel>();
  winrt::get_self<winrt::upx_killer::implementation::ConfigurationViewModel>(viewModel)->Initialize(
      m_ownerWindowHandle, m_settingsStore, m_folderPicker);

  bool const navigated =
      m_frame.Navigate(winrt::xaml_typename<winrt::upx_killer::ConfigurationPage>(), viewModel);
  if (navigated) m_currentRoute = ConfigurationRoute;
  return navigated;
}
}
