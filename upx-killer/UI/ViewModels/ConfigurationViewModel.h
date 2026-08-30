#pragma once

#include "ConfigurationViewModel.g.h"

#include "Application/TemporaryFiles/TemporaryFileSettingsWorkflow.h"
#include "UI/ViewModels/RelayCommand.h"

#include <memory>

#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>

namespace winrt::upx_killer::implementation {
struct ConfigurationViewModel : ConfigurationViewModelT<ConfigurationViewModel> {
  ConfigurationViewModel();

  winrt::hstring TemporaryDirectory() const;
  std::int32_t AutoDeleteSelectedIndex() const noexcept;
  void AutoDeleteSelectedIndex(std::int32_t value);
  winrt::hstring AutoDeleteHelpText() const;
  winrt::Microsoft::UI::Xaml::Input::ICommand SelectTemporaryDirectoryCommand() const;

  winrt::event_token PropertyChanged(
      winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler const& handler);
  void PropertyChanged(winrt::event_token const& token) noexcept;

  void Initialize(std::uintptr_t ownerWindowHandle,
                  std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> store,
                  std::shared_ptr<::upx_killer::application::ITemporaryFolderPicker> folderPicker);

 private:
  winrt::fire_and_forget SelectTemporaryDirectoryAsync();
  void Reload();
  void RaisePropertyChanged(wchar_t const* propertyName);

  winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader m_resources;
  std::uintptr_t m_ownerWindowHandle{};
  winrt::hstring m_temporaryDirectory{L"\u2014"};
  std::int32_t m_autoDeleteSelectedIndex{};
  std::unique_ptr<::upx_killer::application::TemporaryFileSettingsWorkflow> m_workflow;
  winrt::com_ptr<::upx_killer::ui::RelayCommand> m_selectTemporaryDirectoryCommand;
  winrt::event<winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler> m_propertyChanged;
};
}

namespace winrt::upx_killer::factory_implementation {
struct ConfigurationViewModel
    : ConfigurationViewModelT<ConfigurationViewModel, implementation::ConfigurationViewModel> {};
}
