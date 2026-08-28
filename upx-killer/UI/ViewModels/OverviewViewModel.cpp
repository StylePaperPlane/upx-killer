#include "pch.h"
#include "UI/ViewModels/OverviewViewModel.h"
#if __has_include("OverviewViewModel.g.cpp")
#include "OverviewViewModel.g.cpp"
#endif

#include <iomanip>
#include <sstream>

namespace winrt::upx_killer::implementation
{
    OverviewViewModel::OverviewViewModel()
        : m_resources()
    {
        m_statusText = Resource(L"StatusReady");

        m_selectTargetCommand = winrt::make_self<::upx_killer::ui::RelayCommand>(
            [this]() { SelectTargetAsync(); },
            [this]() { return m_targetSelectionWorkflow && m_windowId.Value != 0 && !m_busy; });
        m_startUnpackCommand = winrt::make_self<::upx_killer::ui::RelayCommand>(
            [this]() { StartUnpackAsync(); },
            [this]() { return CanStart(); });
        m_exportCommand = winrt::make_self<::upx_killer::ui::RelayCommand>(
            [this]() { ExportAsync(); },
            [this]() { return CanExport(); });
    }

    winrt::hstring OverviewViewModel::TargetPath() const { return m_targetPathText; }
    winrt::hstring OverviewViewModel::FileSizeText() const { return m_fileSizeText; }
    winrt::hstring OverviewViewModel::FileTypeText() const { return m_fileTypeText; }
    winrt::hstring OverviewViewModel::ArchitectureText() const { return m_architectureText; }
    winrt::hstring OverviewViewModel::StatusText() const { return m_statusText; }
    winrt::upx_killer::OverviewStatusKind OverviewViewModel::StatusKind() const noexcept { return m_statusKind; }
    bool OverviewViewModel::CanStart() const noexcept { return m_hasValidTarget && m_engineCompatible && !m_busy; }
    bool OverviewViewModel::CanExport() const noexcept { return m_hasOutput && !m_busy; }

    winrt::Microsoft::UI::Xaml::Input::ICommand OverviewViewModel::SelectTargetCommand() const
    {
        return m_selectTargetCommand.as<winrt::Microsoft::UI::Xaml::Input::ICommand>();
    }

    winrt::Microsoft::UI::Xaml::Input::ICommand OverviewViewModel::StartUnpackCommand() const
    {
        return m_startUnpackCommand.as<winrt::Microsoft::UI::Xaml::Input::ICommand>();
    }

    winrt::Microsoft::UI::Xaml::Input::ICommand OverviewViewModel::ExportCommand() const
    {
        return m_exportCommand.as<winrt::Microsoft::UI::Xaml::Input::ICommand>();
    }

    winrt::event_token OverviewViewModel::PropertyChanged(
        winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventHandler const& handler)
    {
        return m_propertyChanged.add(handler);
    }

    void OverviewViewModel::PropertyChanged(winrt::event_token const& token) noexcept
    {
        m_propertyChanged.remove(token);
    }

    void OverviewViewModel::Initialize(
        winrt::Microsoft::UI::WindowId const& windowId,
        std::shared_ptr<::upx_killer::application::ITargetFilePicker> picker,
        std::shared_ptr<::upx_killer::application::IUnpackEngineClient> engineClient,
        std::shared_ptr<::upx_killer::application::IArtifactExporter> artifactExporter,
        std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> settingsStore)
    {
        m_windowId = windowId;
        m_targetSelectionWorkflow =
            std::make_unique<::upx_killer::application::TargetSelectionWorkflow>(std::move(picker));
        m_unpackWorkflow =
            std::make_unique<::upx_killer::application::UnpackWorkflow>(std::move(engineClient));
        m_artifactExporter = std::move(artifactExporter);
        m_settingsStore = std::move(settingsStore);
        RaiseCommandStates();
    }

    void OverviewViewModel::LoadTargetPath(winrt::hstring const& pathText)
    {
        if (!m_targetSelectionWorkflow || pathText.empty())
        {
            ReportDropFailure();
            return;
        }

        auto const path = std::filesystem::path{ pathText.c_str() };
        ApplyInspectionResult(path, m_targetSelectionWorkflow->Inspect(path));
    }

    void OverviewViewModel::ReportInvalidDrop()
    {
        SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusInvalidDrop");
    }

    void OverviewViewModel::ReportDropFailure()
    {
        SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusDropFailure");
    }

    winrt::fire_and_forget OverviewViewModel::SelectTargetAsync()
    {
        auto lifetime = get_strong();
        m_busy = true;
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();

        try
        {
            auto const selectedPath = co_await m_targetSelectionWorkflow->SelectPathAsync(m_windowId);
            if (!selectedPath.empty())
            {
                LoadTargetPath(selectedPath);
            }
        }
        catch (...)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusIoError");
        }

        m_busy = false;
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();
    }

    winrt::fire_and_forget OverviewViewModel::StartUnpackAsync()
    {
        if (!CanStart())
        {
            co_return;
        }

        if (!m_unpackWorkflow)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Unavailable, L"StatusEngineUnavailable");
            co_return;
        }

        auto lifetime = get_strong();
        winrt::apartment_context uiContext;
        auto dispatcher = winrt::Microsoft::UI::Dispatching::DispatcherQueue::GetForCurrentThread();
        auto const targetPath = m_targetPath;
        m_busy = true;
        SetStatus(winrt::upx_killer::OverviewStatusKind::Busy, L"StatusFindingOep");
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();
        co_await winrt::resume_background();
        auto const progress = [lifetime, dispatcher](::upx_killer::engine::EngineStage stage)
        {
            if (!dispatcher) return;
            dispatcher.TryEnqueue([lifetime, stage]() { lifetime->SetProgress(stage); });
        };
        auto const result = m_unpackWorkflow->Start(targetPath, std::nullopt, progress);
        co_await uiContext;
        m_busy = false;
        if (result.outcome == ::upx_killer::application::UnpackOutcome::NeedsOep)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Unavailable, L"StatusOepRequired");
            RaisePropertyChanged(L"CanStart");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::UnsupportedPacker)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusUnsupportedPacker");
            RaisePropertyChanged(L"CanStart");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::OepNotFound)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusOepNotFound");
            RaisePropertyChanged(L"CanStart");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::ImportsNotFound ||
            result.outcome == ::upx_killer::application::UnpackOutcome::ImportsAmbiguous)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusImportsNotRebuilt");
            RaisePropertyChanged(L"CanStart");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::RelocationEvidenceFailed)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusRelocationEvidenceFailed");
            RaisePropertyChanged(L"CanStart");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::RelocationValidationFailed)
        {
            SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusRelocationValidationFailed");
            RaisePropertyChanged(L"CanStart");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::Partial)
        {
            m_outputPath = result.outputPath;
            m_hasOutput = true;
            SetStatus(winrt::upx_killer::OverviewStatusKind::Unavailable, L"StatusPartialImportsNotRebuilt");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        if (result.outcome == ::upx_killer::application::UnpackOutcome::Succeeded)
        {
            m_outputPath = result.outputPath;
            m_hasOutput = true;
            SetStatus(winrt::upx_killer::OverviewStatusKind::Succeeded, L"StatusUnpackSucceeded");
            RaisePropertyChanged(L"CanExport");
            RaiseCommandStates();
            co_return;
        }

        SetStatus(winrt::upx_killer::OverviewStatusKind::Error, L"StatusUnpackFailed");
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();
    }

    winrt::fire_and_forget OverviewViewModel::ExportAsync()
    {
        if (!CanExport())
        {
            co_return;
        }

        auto lifetime = get_strong();
        m_busy = true;
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();
        bool exported{};
        try
        {
            exported = m_artifactExporter &&
                co_await m_artifactExporter->ExportAsync(m_windowId, m_outputPath);
        }
        catch (...)
        {
            exported = false;
        }
        m_busy = false;
        if (exported && m_settingsStore && m_settingsStore->Load().deleteAfterExport)
        {
            m_hasOutput = false;
            m_outputPath.clear();
        }
        SetStatus(
            exported ? winrt::upx_killer::OverviewStatusKind::Succeeded : winrt::upx_killer::OverviewStatusKind::Error,
            exported ? L"StatusExportSucceeded" : L"StatusExportFailed");
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();
    }

    void OverviewViewModel::ApplyInspectionResult(
        std::filesystem::path const& path,
        ::upx_killer::core::InspectionResult const& result)
    {
        m_targetPath = path;
        m_targetPathText = winrt::hstring{ path.wstring() };
        m_hasOutput = false;
        m_outputPath.clear();

        if (result.Succeeded())
        {
            auto const& info = *result.info;
            m_fileSizeText = FormatFileSize(info.fileSize);
            m_fileTypeText = FormatBinaryType(info.format);
            m_architectureText = FormatArchitecture(info.architecture);
            m_hasValidTarget = true;
            m_engineCompatible =
                info.format == ::upx_killer::core::BinaryFormat::Pe32PlusExecutable &&
                info.architecture == ::upx_killer::core::BinaryArchitecture::X64;
            SetStatus(
                m_engineCompatible ? winrt::upx_killer::OverviewStatusKind::Ready : winrt::upx_killer::OverviewStatusKind::Unavailable,
                m_engineCompatible ? L"StatusTargetReady" : L"StatusEngineX64PeOnly");
        }
        else
        {
            m_fileSizeText = L"\u2014";
            m_fileTypeText = L"\u2014";
            m_architectureText = L"\u2014";
            m_hasValidTarget = false;
            m_engineCompatible = false;
            m_statusKind = winrt::upx_killer::OverviewStatusKind::Error;
            m_statusText = FormatInspectionError(result.error);
            RaisePropertyChanged(L"StatusKind");
            RaisePropertyChanged(L"StatusText");
        }

        RaisePropertyChanged(L"TargetPath");
        RaisePropertyChanged(L"FileSizeText");
        RaisePropertyChanged(L"FileTypeText");
        RaisePropertyChanged(L"ArchitectureText");
        RaisePropertyChanged(L"CanStart");
        RaisePropertyChanged(L"CanExport");
        RaiseCommandStates();
    }

    void OverviewViewModel::SetStatus(
        winrt::upx_killer::OverviewStatusKind kind,
        wchar_t const* resourceKey)
    {
        m_statusKind = kind;
        m_statusText = Resource(resourceKey);
        RaisePropertyChanged(L"StatusKind");
        RaisePropertyChanged(L"StatusText");
    }

    void OverviewViewModel::SetProgress(::upx_killer::engine::EngineStage stage)
    {
        wchar_t const* resourceKey{};
        switch (stage)
        {
        case ::upx_killer::engine::EngineStage::DiscoveringOep:
            resourceKey = L"StatusFindingOep";
            break;
        case ::upx_killer::engine::EngineStage::CapturingRelocations:
            resourceKey = L"StatusCapturingRelocations";
            break;
        case ::upx_killer::engine::EngineStage::RebuildingRelocations:
            resourceKey = L"StatusRebuildingRelocations";
            break;
        case ::upx_killer::engine::EngineStage::RebuildingImports:
            resourceKey = L"StatusRebuildingImports";
            break;
        case ::upx_killer::engine::EngineStage::Dumping:
            resourceKey = L"StatusDumping";
            break;
        default:
            break;
        }

        if (resourceKey)
            SetStatus(winrt::upx_killer::OverviewStatusKind::Busy, resourceKey);
    }

    void OverviewViewModel::RaisePropertyChanged(wchar_t const* propertyName)
    {
        m_propertyChanged(*this, winrt::Microsoft::UI::Xaml::Data::PropertyChangedEventArgs{ propertyName });
    }

    void OverviewViewModel::RaiseCommandStates()
    {
        m_selectTargetCommand->RaiseCanExecuteChanged();
        m_startUnpackCommand->RaiseCanExecuteChanged();
        m_exportCommand->RaiseCanExecuteChanged();
    }

    winrt::hstring OverviewViewModel::Resource(wchar_t const* resourceKey) const
    {
        return m_resources.GetString(resourceKey);
    }

    winrt::hstring OverviewViewModel::FormatFileSize(std::uint64_t bytes) const
    {
        constexpr double BytesPerKilobyte = 1024.0;
        constexpr double BytesPerMegabyte = BytesPerKilobyte * 1024.0;

        std::wostringstream stream;
        if (bytes >= static_cast<std::uint64_t>(BytesPerMegabyte))
        {
            stream << std::fixed << std::setprecision(2)
                   << static_cast<double>(bytes) / BytesPerMegabyte << L" MB";
        }
        else if (bytes >= static_cast<std::uint64_t>(BytesPerKilobyte))
        {
            stream << std::fixed << std::setprecision(2)
                   << static_cast<double>(bytes) / BytesPerKilobyte << L" KB";
        }
        else
        {
            stream << bytes << L" " << Resource(L"BytesUnit").c_str();
        }

        return winrt::hstring{ stream.str() };
    }

    winrt::hstring OverviewViewModel::FormatBinaryType(::upx_killer::core::BinaryFormat format) const
    {
        using ::upx_killer::core::BinaryFormat;
        switch (format)
        {
        case BinaryFormat::Pe32Executable: return Resource(L"BinaryPe32Executable");
        case BinaryFormat::Pe32PlusExecutable: return Resource(L"BinaryPe32PlusExecutable");
        case BinaryFormat::Pe32Library: return Resource(L"BinaryPe32Library");
        case BinaryFormat::Pe32PlusLibrary: return Resource(L"BinaryPe32PlusLibrary");
        case BinaryFormat::Elf32Executable: return Resource(L"BinaryElf32Executable");
        case BinaryFormat::Elf64Executable: return Resource(L"BinaryElf64Executable");
        case BinaryFormat::Elf32SharedObject: return Resource(L"BinaryElf32SharedObject");
        case BinaryFormat::Elf64SharedObject: return Resource(L"BinaryElf64SharedObject");
        }

        return Resource(L"BinaryUnknown");
    }

    winrt::hstring OverviewViewModel::FormatArchitecture(::upx_killer::core::BinaryArchitecture architecture) const
    {
        return architecture == ::upx_killer::core::BinaryArchitecture::X86 ? L"x86" : L"x64";
    }

    winrt::hstring OverviewViewModel::FormatInspectionError(::upx_killer::core::InspectionError error) const
    {
        using ::upx_killer::core::InspectionError;
        switch (error)
        {
        case InspectionError::FileNotFound: return Resource(L"StatusFileNotFound");
        case InspectionError::AccessDenied: return Resource(L"StatusAccessDenied");
        case InspectionError::TruncatedFile: return Resource(L"StatusTruncatedFile");
        case InspectionError::UnsupportedFormat: return Resource(L"StatusUnsupportedFormat");
        case InspectionError::UnsupportedArchitecture: return Resource(L"StatusUnsupportedArchitecture");
        case InspectionError::IoFailure: return Resource(L"StatusIoError");
        case InspectionError::None: break;
        }

        return Resource(L"StatusIoError");
    }
}
