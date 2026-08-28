#pragma once

#include "Application/TemporaryFiles/ITemporaryFolderPicker.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"

#include <memory>

namespace upx_killer::application
{
    class TemporaryFileSettingsWorkflow final
    {
    public:
        TemporaryFileSettingsWorkflow(
            std::shared_ptr<ITemporaryFileSettingsStore> store,
            std::shared_ptr<ITemporaryFolderPicker> folderPicker);

        [[nodiscard]] TemporaryFileSettings Load() const noexcept;
        [[nodiscard]] winrt::Windows::Foundation::IAsyncOperation<bool> SelectDirectoryAsync(
            std::uintptr_t ownerWindowHandle);
        [[nodiscard]] bool SetDeleteAfterExport(bool enabled) noexcept;

    private:
        std::shared_ptr<ITemporaryFileSettingsStore> m_store;
        std::shared_ptr<ITemporaryFolderPicker> m_folderPicker;
    };
}
