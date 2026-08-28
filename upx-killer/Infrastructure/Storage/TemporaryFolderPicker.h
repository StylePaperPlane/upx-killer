#pragma once

#include "Application/TemporaryFiles/ITemporaryFolderPicker.h"

namespace upx_killer::infrastructure
{
    class TemporaryFolderPicker final : public application::ITemporaryFolderPicker
    {
    public:
        [[nodiscard]] winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> PickAsync(
            std::uintptr_t ownerWindowHandle) override;
    };
}
