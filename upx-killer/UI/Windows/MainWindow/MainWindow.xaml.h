#pragma once

#define WINRT_FORCE_INCLUDE_MAINWINDOW_XAML_G_H
#include "MainWindow.g.h"

#include "UI/Navigation/NavigationRouter.h"

#include <memory>
#include <cstdint>
#include <vector>

namespace upx_killer::ui {
class NavigationPaneController;
}

namespace winrt::upx_killer::implementation {
struct MainWindow : MainWindowT<MainWindow> {
  MainWindow();
  ~MainWindow();

  void InitializeShell(
      std::vector<::upx_killer::ui::NavigationRouteRegistration> routes);

 private:
  void OnNavigationSelectionChanged(
      winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
      winrt::Microsoft::UI::Xaml::Controls::NavigationViewSelectionChangedEventArgs const& args);

  std::unique_ptr<::upx_killer::ui::NavigationPaneController> m_navigationPaneController;
  std::unique_ptr<::upx_killer::ui::NavigationRouter> m_navigationRouter;
  std::uintptr_t m_windowHandle{};
};
}

namespace winrt::upx_killer::factory_implementation {
struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow> {};
}
