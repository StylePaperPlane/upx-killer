#pragma once

#include "Application/Unpacking/IArtifactExporter.h"

namespace upx_killer::infrastructure
{
    class ArtifactFileExporter final : public application::IArtifactExporter
    {
    public:
        [[nodiscard]] winrt::Windows::Foundation::IAsyncOperation<bool> ExportAsync(
            winrt::Microsoft::UI::WindowId const& windowId,
            std::filesystem::path const& artifactPath) override;
    };
}
