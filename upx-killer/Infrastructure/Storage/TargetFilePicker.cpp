#include "pch.h"
#include "Infrastructure/Storage/TargetFilePicker.h"

#include <winrt/Microsoft.Windows.Storage.Pickers.h>

namespace upx_killer::infrastructure
{
    winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> TargetFilePicker::PickAsync(
        winrt::Microsoft::UI::WindowId const& windowId)
    {
        using namespace winrt::Microsoft::Windows::Storage::Pickers;

        FileOpenPicker picker{ windowId };
        picker.SuggestedStartLocation(PickerLocationId::ComputerFolder);
        picker.ViewMode(PickerViewMode::List);
        picker.FileTypeFilter().Append(L".exe");
        picker.FileTypeFilter().Append(L".dll");
        picker.FileTypeFilter().Append(L".elf");
        picker.FileTypeFilter().Append(L".so");

        auto const result = co_await picker.PickSingleFileAsync();
        co_return result ? result.Path() : winrt::hstring{};
    }
}
