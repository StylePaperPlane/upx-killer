#pragma once

#include "ConfigurationViewModel.g.h"

#include "Application/TemporaryFiles/TemporaryFileSettingsWorkflow.h"
#include "Application/Runtime/WslRuntimeSettingsWorkflow.h"
#include "UI/ViewModels/RelayCommand.h"

#include <memory>
#include <vector>

#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>
#include <winrt/Windows.Foundation.Collections.h>

namespace winrt::upx_killer::implementation {
struct ConfigurationViewModel : ConfigurationViewModelT<ConfigurationViewModel> {
  ConfigurationViewModel();

  winrt::hstring TemporaryDirectory() const;
  std::int32_t AutoDeleteSelectedIndex() const noexcept;
  void AutoDeleteSelectedIndex(std::int32_t value);
  winrt::hstring AutoDeleteHelpText() const;
  winrt::Microsoft::UI::Xaml::Input::ICommand SelectTemporaryDirectoryCommand() const;
  winrt::Windows::Foundation::Collections::IVector<winrt::hstring>
  WslDistributions() const;
  std::int32_t SelectedWslDistributionIndex() const noexcept;
  void SelectedWslDistributionIndex(std::int32_t value);
  winrt::Microsoft::UI::Xaml::Input::ICommand
  RefreshWslDistributionsCommand() const;

  winrt::event_token PropertyChanged(
      winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler const& handler);
  void PropertyChanged(winrt::event_token const& token) noexcept;

  void Initialize(std::uintptr_t ownerWindowHandle,
                  std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> store,
                  std::shared_ptr<::upx_killer::application::ITemporaryFolderPicker> folderPicker,
                  std::shared_ptr<::upx_killer::application::IWslRuntimeSettingsStore> wslStore,
                  std::shared_ptr<::upx_killer::application::IWslDistributionCatalog> wslCatalog);

 private:
  winrt::fire_and_forget SelectTemporaryDirectoryAsync();
  void Reload();
  winrt::fire_and_forget RefreshWslDistributionsAsync();
  void RaisePropertyChanged(wchar_t const* propertyName);

  winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader m_resources;
  std::uintptr_t m_ownerWindowHandle{};
  winrt::hstring m_temporaryDirectory{L"\u2014"};
  std::int32_t m_autoDeleteSelectedIndex{};
  std::unique_ptr<::upx_killer::application::TemporaryFileSettingsWorkflow> m_workflow;
  std::unique_ptr<::upx_killer::application::WslRuntimeSettingsWorkflow> m_wslWorkflow;
  std::vector<::upx_killer::application::WslDistributionInfo> m_wslEntries;
  winrt::Windows::Foundation::Collections::IObservableVector<winrt::hstring>
      m_wslDistributions{winrt::single_threaded_observable_vector<winrt::hstring>()};
  std::int32_t m_selectedWslDistributionIndex{-1};
  bool m_wslRefreshInProgress{};
  winrt::com_ptr<::upx_killer::ui::RelayCommand> m_selectTemporaryDirectoryCommand;
  winrt::com_ptr<::upx_killer::ui::RelayCommand> m_refreshWslDistributionsCommand;
  winrt::event<winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler> m_propertyChanged;
};
}

namespace winrt::upx_killer::factory_implementation {
struct ConfigurationViewModel
    : ConfigurationViewModelT<ConfigurationViewModel, implementation::ConfigurationViewModel> {};
}
