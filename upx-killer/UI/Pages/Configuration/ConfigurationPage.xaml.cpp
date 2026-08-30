#include "pch.h"
#include "UI/Pages/Configuration/ConfigurationPage.xaml.h"
#if __has_include("ConfigurationPage.g.cpp")
#include "ConfigurationPage.g.cpp"
#endif

#include "UI/ViewModels/ConfigurationViewModel.h"

#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>

namespace winrt::upx_killer::implementation {
ConfigurationPage::ConfigurationPage()
    : m_viewModel(winrt::make<implementation::ConfigurationViewModel>()) {
  InitializeComponent();

  auto const resources = winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader{};
  using winrt::Microsoft::UI::Xaml::Automation::AutomationProperties;
  AutomationProperties::SetName(TemporaryDirectoryTextBox(),
                                resources.GetString(L"TemporaryDirectoryAutomationName"));
  AutomationProperties::SetName(SelectTemporaryDirectoryButton(),
                                resources.GetString(L"SelectTemporaryDirectoryAutomationName"));
  AutomationProperties::SetName(AutoDeleteHelpButton(),
                                resources.GetString(L"AutoDeleteHelpAutomationName"));
  AutomationProperties::SetName(AutoDeleteComboBox(),
                                resources.GetString(L"AutoDeleteAutomationName"));
}

winrt::upx_killer::ConfigurationViewModel ConfigurationPage::ViewModel() const {
  return m_viewModel;
}

void ConfigurationPage::OnNavigatedTo(
    winrt::Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args) {
  auto const viewModel = args.Parameter().try_as<winrt::upx_killer::ConfigurationViewModel>();
  if (viewModel) m_viewModel = viewModel;
}

}
