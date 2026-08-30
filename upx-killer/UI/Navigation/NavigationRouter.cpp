#include "pch.h"
#include "UI/Navigation/NavigationRouter.h"

#include <stdexcept>
#include <utility>

namespace upx_killer::ui {
NavigationRouter::NavigationRouter(
    winrt::Microsoft::UI::Xaml::Controls::Frame const& frame,
    std::vector<NavigationRouteRegistration> registrations)
    : m_frame(frame) {
  if (!m_frame) throw std::invalid_argument("frame");
  for (auto& registration : registrations) {
    if (registration.tag.empty() || !registration.navigate ||
        !m_routes.emplace(std::move(registration.tag),
                          std::move(registration.navigate))
             .second) {
      throw std::invalid_argument("registrations");
    }
  }
}

bool NavigationRouter::Navigate(winrt::hstring const& routeTag) {
  if (routeTag == m_currentRoute && m_frame.Content()) return true;
  auto const route = m_routes.find(std::wstring{routeTag});
  if (route == m_routes.end() || !route->second(m_frame)) return false;
  m_currentRoute = routeTag;
  return true;
}
}
