#include "pch.h"
#include "Infrastructure/Storage/ArtifactFileExporter.h"

#include <winrt/Microsoft.Windows.Storage.Pickers.h>

namespace upx_killer::infrastructure
{
    ArtifactFileExporter::ArtifactFileExporter(
        std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore)
        : m_settingsStore(std::move(settingsStore))
    {
    }

    winrt::Windows::Foundation::IAsyncOperation<bool> ArtifactFileExporter::ExportAsync(
        winrt::Microsoft::UI::WindowId const& windowId,
        std::filesystem::path const& artifactPath)
    {
        using namespace winrt::Microsoft::Windows::Storage::Pickers;

        if (!std::filesystem::is_regular_file(artifactPath)) co_return false;
        FileSavePicker picker{ windowId };
        picker.SuggestedStartLocation(PickerLocationId::DocumentsLibrary);
        picker.SuggestedFileName(winrt::hstring{ artifactPath.stem().wstring() });
        picker.DefaultFileExtension(L".exe");
        auto extensions = winrt::single_threaded_vector<winrt::hstring>();
        extensions.Append(L".exe");
        picker.FileTypeChoices().Insert(L"*.exe", extensions);
        auto const destination = co_await picker.PickSaveFileAsync();
        if (!destination) co_return false;
        if (!CopyFileW(artifactPath.c_str(), destination.Path().c_str(), FALSE)) co_return false;

        if (m_settingsStore && m_settingsStore->Load().deleteAfterExport)
        {
            std::error_code error;
            std::filesystem::remove(artifactPath, error);
            if (!error)
                std::filesystem::remove(artifactPath.parent_path(), error);
        }

        co_return true;
    }
}
