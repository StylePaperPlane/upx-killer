#pragma once

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include <winrt/Microsoft.UI.Xaml.Controls.h>

namespace upx_killer::ui {
struct NavigationRouteRegistration {
  std::wstring tag;
  std::function<bool(
      winrt::Microsoft::UI::Xaml::Controls::Frame const&)> navigate;
};

class NavigationRouter final {
 public:
  NavigationRouter(
      winrt::Microsoft::UI::Xaml::Controls::Frame const& frame,
      std::vector<NavigationRouteRegistration> registrations);
  [[nodiscard]] bool Navigate(winrt::hstring const& routeTag);

 private:
  winrt::Microsoft::UI::Xaml::Controls::Frame m_frame{nullptr};
  std::unordered_map<
      std::wstring,
      std::function<bool(
          winrt::Microsoft::UI::Xaml::Controls::Frame const&)>>
      m_routes;
  winrt::hstring m_currentRoute;
};
}
