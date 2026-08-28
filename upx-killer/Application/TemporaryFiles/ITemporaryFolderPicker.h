#pragma once

#include <cstdint>

#include <winrt/Windows.Foundation.h>

namespace upx_killer::application
{
    class ITemporaryFolderPicker
    {
    public:
        virtual ~ITemporaryFolderPicker() = default;
        [[nodiscard]] virtual winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> PickAsync(
            std::uintptr_t ownerWindowHandle) = 0;
    };
}
