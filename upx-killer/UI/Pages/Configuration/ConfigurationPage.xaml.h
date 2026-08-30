#pragma once

#define WINRT_FORCE_INCLUDE_CONFIGURATIONPAGE_XAML_G_H
#include "ConfigurationPage.g.h"

#include <winrt/Microsoft.UI.Xaml.Navigation.h>

namespace winrt::upx_killer::implementation {
struct ConfigurationPage : ConfigurationPageT<ConfigurationPage> {
  ConfigurationPage();

  winrt::upx_killer::ConfigurationViewModel ViewModel() const;
  void OnNavigatedTo(winrt::Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);

 private:
  winrt::upx_killer::ConfigurationViewModel m_viewModel{nullptr};
};
}

namespace winrt::upx_killer::factory_implementation {
struct ConfigurationPage
    : ConfigurationPageT<ConfigurationPage, implementation::ConfigurationPage> {};
}
