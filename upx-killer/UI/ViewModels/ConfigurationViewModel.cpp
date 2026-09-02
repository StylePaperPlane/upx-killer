#include "pch.h"
#include "UI/ViewModels/ConfigurationViewModel.h"
#if __has_include("ConfigurationViewModel.g.cpp")
#include "ConfigurationViewModel.g.cpp"
#endif

namespace winrt::upx_killer::implementation {
ConfigurationViewModel::ConfigurationViewModel() : m_resources() {
  m_selectTemporaryDirectoryCommand = winrt::make_self<::upx_killer::ui::RelayCommand>(
      [this]() { SelectTemporaryDirectoryAsync(); },
      [this]() { return m_workflow && m_ownerWindowHandle != 0; });
  m_refreshWslDistributionsCommand =
      winrt::make_self<::upx_killer::ui::RelayCommand>(
          [this]() { RefreshWslDistributionsAsync(); },
          [this]() {
            return m_wslWorkflow != nullptr && !m_wslRefreshInProgress;
          });
}

winrt::hstring ConfigurationViewModel::TemporaryDirectory() const { return m_temporaryDirectory; }

std::int32_t ConfigurationViewModel::AutoDeleteSelectedIndex() const noexcept {
  return m_autoDeleteSelectedIndex;
}

void ConfigurationViewModel::AutoDeleteSelectedIndex(std::int32_t value) {
  if (!m_workflow || value < 0 || value > 1 || value == m_autoDeleteSelectedIndex) return;
  if (!m_workflow->SetDeleteAfterExport(value == 0)) return;
  m_autoDeleteSelectedIndex = value;
  RaisePropertyChanged(L"AutoDeleteSelectedIndex");
}

winrt::hstring ConfigurationViewModel::AutoDeleteHelpText() const {
  return m_resources.GetString(L"TemporaryFilesRetentionHelp");
}

winrt::Microsoft::UI::Xaml::Input::ICommand
ConfigurationViewModel::SelectTemporaryDirectoryCommand() const {
  return m_selectTemporaryDirectoryCommand.as<winrt::Microsoft::UI::Xaml::Input::ICommand>();
}

winrt::Windows::Foundation::Collections::IVector<winrt::hstring>
ConfigurationViewModel::WslDistributions() const {
  return m_wslDistributions;
}

std::int32_t ConfigurationViewModel::SelectedWslDistributionIndex() const noexcept {
  return m_selectedWslDistributionIndex;
}

void ConfigurationViewModel::SelectedWslDistributionIndex(std::int32_t value) {
  if (!m_wslWorkflow || value < 0 ||
      static_cast<std::size_t>(value) >= m_wslEntries.size() ||
      value == m_selectedWslDistributionIndex)
    return;
  if (!m_wslWorkflow->Select(m_wslEntries[static_cast<std::size_t>(value)].name))
    return;
  m_selectedWslDistributionIndex = value;
  RaisePropertyChanged(L"SelectedWslDistributionIndex");
}

winrt::Microsoft::UI::Xaml::Input::ICommand
ConfigurationViewModel::RefreshWslDistributionsCommand() const {
  return m_refreshWslDistributionsCommand
      .as<winrt::Microsoft::UI::Xaml::Input::ICommand>();
}

winrt::event_token ConfigurationViewModel::PropertyChanged(
    winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler const& handler) {
  return m_propertyChanged.add(handler);
}

void ConfigurationViewModel::PropertyChanged(winrt::event_token const& token) noexcept {
  m_propertyChanged.remove(token);
}

void ConfigurationViewModel::Initialize(
    std::uintptr_t ownerWindowHandle,
    std::unique_ptr<::upx_killer::application::TemporaryFileSettingsWorkflow>
        temporaryFilesWorkflow,
    std::unique_ptr<::upx_killer::application::WslRuntimeSettingsWorkflow>
        wslWorkflow) {
  m_ownerWindowHandle = ownerWindowHandle;
  m_workflow = std::move(temporaryFilesWorkflow);
  m_wslWorkflow = std::move(wslWorkflow);
  Reload();
  RefreshWslDistributionsAsync();
  m_selectTemporaryDirectoryCommand->RaiseCanExecuteChanged();
  m_refreshWslDistributionsCommand->RaiseCanExecuteChanged();
}

winrt::fire_and_forget
ConfigurationViewModel::RefreshWslDistributionsAsync() {
  auto lifetime = get_strong();
  if (!m_wslWorkflow || m_wslRefreshInProgress) co_return;
  m_wslRefreshInProgress = true;
  m_refreshWslDistributionsCommand->RaiseCanExecuteChanged();
  winrt::apartment_context uiContext;
  auto const selected = m_wslWorkflow->Load().distribution;
  auto* workflow = m_wslWorkflow.get();
  co_await winrt::resume_background();
  auto entries = workflow->Refresh();
  co_await uiContext;
  m_wslEntries = std::move(entries);
  m_wslDistributions.Clear();
  m_selectedWslDistributionIndex = -1;
  for (std::size_t index = 0; index < m_wslEntries.size(); ++index) {
    m_wslDistributions.Append(winrt::hstring{m_wslEntries[index].name});
    if (m_wslEntries[index].name == selected)
      m_selectedWslDistributionIndex = static_cast<std::int32_t>(index);
  }
  if (m_selectedWslDistributionIndex < 0 && !m_wslEntries.empty()) {
    m_selectedWslDistributionIndex = 0;
    static_cast<void>(m_wslWorkflow->Select(m_wslEntries.front().name));
  }
  RaisePropertyChanged(L"WslDistributions");
  RaisePropertyChanged(L"SelectedWslDistributionIndex");
  m_wslRefreshInProgress = false;
  m_refreshWslDistributionsCommand->RaiseCanExecuteChanged();
}

winrt::fire_and_forget ConfigurationViewModel::SelectTemporaryDirectoryAsync() {
  auto lifetime = get_strong();
  try {
    if (co_await m_workflow->SelectDirectoryAsync(m_ownerWindowHandle)) Reload();
  } catch (...) {
  }
}

void ConfigurationViewModel::Reload() {
  auto const settings = m_workflow->Load();
  m_temporaryDirectory = winrt::hstring{settings.directory.wstring()};
  m_autoDeleteSelectedIndex = settings.deleteAfterExport ? 0 : 1;
  RaisePropertyChanged(L"TemporaryDirectory");
  RaisePropertyChanged(L"AutoDeleteSelectedIndex");
}

void ConfigurationViewModel::RaisePropertyChanged(wchar_t const* propertyName) {
  m_propertyChanged(*this,
                    winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventArgs{propertyName});
}
}
