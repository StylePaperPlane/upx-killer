#pragma once

#include "Application/Unpacking/IArtifactExporter.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"

#include <memory>

namespace upx_killer::infrastructure
{
    class ArtifactFileExporter final : public application::IArtifactExporter
    {
    public:
        explicit ArtifactFileExporter(
            std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore);

        [[nodiscard]] winrt::Windows::Foundation::IAsyncOperation<bool> ExportAsync(
            winrt::Microsoft::UI::WindowId const& windowId,
            std::filesystem::path const& artifactPath) override;

    private:
        std::shared_ptr<application::ITemporaryFileSettingsStore> m_settingsStore;
    };
}
