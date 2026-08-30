#pragma once

#include "OverviewViewModel.g.h"

#include "Application/TargetSelection/TargetSelectionWorkflow.h"
#include "Application/Unpacking/UnpackWorkflow.h"
#include "Application/Unpacking/IArtifactExporter.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"
#include "Core/BinaryInspection/TargetBinaryInspector.h"
#include "UI/ViewModels/RelayCommand.h"

#include <filesystem>
#include <memory>

#include <winrt/Microsoft.UI.h>
#include <winrt/Microsoft.UI.Dispatching.h>
#include <winrt/Microsoft.UI.Xaml.Data.h>
#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>

namespace winrt::upx_killer::implementation {
struct OverviewViewModel : OverviewViewModelT<OverviewViewModel> {
  OverviewViewModel();

  winrt::hstring TargetPath() const;
  winrt::hstring FileSizeText() const;
  winrt::hstring FileTypeText() const;
  winrt::hstring ArchitectureText() const;
  winrt::hstring StatusText() const;
  winrt::upx_killer::OverviewStatusKind StatusKind() const noexcept;
  bool CanStart() const noexcept;
  bool CanExport() const noexcept;

  winrt::Microsoft::UI::Xaml::Input::ICommand SelectTargetCommand() const;
  winrt::Microsoft::UI::Xaml::Input::ICommand StartUnpackCommand() const;
  winrt::Microsoft::UI::Xaml::Input::ICommand ExportCommand() const;

  winrt::event_token PropertyChanged(
      winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler const& handler);
  void PropertyChanged(winrt::event_token const& token) noexcept;

  void Initialize(
      winrt::Microsoft::UI::WindowId const& windowId,
      std::shared_ptr<::upx_killer::application::ITargetFilePicker> picker,
      std::shared_ptr<::upx_killer::application::IUnpackEngineClient> engineClient,
      std::shared_ptr<::upx_killer::application::IArtifactExporter> artifactExporter,
      std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> settingsStore);
  void LoadTargetPath(winrt::hstring const& path);
  void ReportInvalidDrop();
  void ReportDropFailure();

 private:
  winrt::fire_and_forget SelectTargetAsync();
  winrt::fire_and_forget RefreshCapabilitiesAsync();
  winrt::fire_and_forget StartUnpackAsync();
  winrt::fire_and_forget ExportAsync();
  void ApplyInspectionResult(std::filesystem::path const& path,
                             ::upx_killer::core::InspectionResult const& result);
  void SetStatus(winrt::upx_killer::OverviewStatusKind kind, wchar_t const* resourceKey);
  void SetProgress(::upx_killer::contracts::ProgressEvent const& event);
  void RaisePropertyChanged(wchar_t const* propertyName);
  void RaiseCommandStates();
  winrt::hstring Resource(wchar_t const* resourceKey) const;
  winrt::hstring FormatFileSize(std::uint64_t bytes) const;
  winrt::hstring FormatBinaryType(::upx_killer::core::BinaryFormat format) const;
  winrt::hstring FormatArchitecture(::upx_killer::core::BinaryArchitecture architecture) const;
  winrt::hstring FormatInspectionError(::upx_killer::core::InspectionError error) const;

  winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader m_resources;
  winrt::Microsoft::UI::WindowId m_windowId{};
  std::filesystem::path m_targetPath;
  winrt::hstring m_targetPathText{L"\u2014"};
  winrt::hstring m_fileSizeText{L"\u2014"};
  winrt::hstring m_fileTypeText{L"\u2014"};
  winrt::hstring m_architectureText{L"\u2014"};
  winrt::hstring m_statusText;
  winrt::upx_killer::OverviewStatusKind m_statusKind{winrt::upx_killer::OverviewStatusKind::Idle};
  bool m_hasValidTarget{};
  std::optional<::upx_killer::contracts::TargetDescriptor> m_targetDescriptor;
  bool m_engineCompatible{};
  bool m_hasOutput{};
  bool m_busy{};
  std::unique_ptr<::upx_killer::application::TargetSelectionWorkflow> m_targetSelectionWorkflow;
  std::unique_ptr<::upx_killer::application::UnpackWorkflow> m_unpackWorkflow;
  std::shared_ptr<::upx_killer::application::IArtifactExporter> m_artifactExporter;
  std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> m_settingsStore;
  std::filesystem::path m_outputPath;
  winrt::com_ptr<::upx_killer::ui::RelayCommand> m_selectTargetCommand;
  winrt::com_ptr<::upx_killer::ui::RelayCommand> m_startUnpackCommand;
  winrt::com_ptr<::upx_killer::ui::RelayCommand> m_exportCommand;
  winrt::event<winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler> m_propertyChanged;
};
}

namespace winrt::upx_killer::factory_implementation {
struct OverviewViewModel
    : OverviewViewModelT<OverviewViewModel, implementation::OverviewViewModel> {};
}
