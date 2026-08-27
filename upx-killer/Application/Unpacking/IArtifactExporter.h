#pragma once

#include <filesystem>

#include <winrt/Microsoft.UI.h>
#include <winrt/Windows.Foundation.h>

namespace upx_killer::application
{
    class IArtifactExporter
    {
    public:
        virtual ~IArtifactExporter() = default;
        [[nodiscard]] virtual winrt::Windows::Foundation::IAsyncOperation<bool> ExportAsync(
            winrt::Microsoft::UI::WindowId const& windowId,
            std::filesystem::path const& artifactPath) = 0;
    };
}
