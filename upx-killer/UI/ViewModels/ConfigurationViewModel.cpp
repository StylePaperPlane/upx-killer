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

winrt::event_token ConfigurationViewModel::PropertyChanged(
    winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler const& handler) {
  return m_propertyChanged.add(handler);
}

void ConfigurationViewModel::PropertyChanged(winrt::event_token const& token) noexcept {
  m_propertyChanged.remove(token);
}

void ConfigurationViewModel::Initialize(
    std::uintptr_t ownerWindowHandle,
    std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> store,
    std::shared_ptr<::upx_killer::application::ITemporaryFolderPicker> folderPicker) {
  m_ownerWindowHandle = ownerWindowHandle;
  m_workflow = std::make_unique<::upx_killer::application::TemporaryFileSettingsWorkflow>(
      std::move(store), std::move(folderPicker));
  Reload();
  m_selectTemporaryDirectoryCommand->RaiseCanExecuteChanged();
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
