#pragma once

#include "Application/TargetSelection/TargetSelectionWorkflow.h"
#include "Application/Unpacking/IUnpackEngineClient.h"
#include "Application/Unpacking/IArtifactExporter.h"

#include <memory>

#include <winrt/Microsoft.UI.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>

namespace upx_killer::ui
{
    class NavigationRouter final
    {
    public:
        NavigationRouter(
            winrt::Microsoft::UI::Xaml::Controls::Frame const& frame,
            winrt::Microsoft::UI::WindowId const& windowId,
            std::shared_ptr<application::ITargetFilePicker> picker,
            std::shared_ptr<application::IUnpackEngineClient> engineClient,
            std::shared_ptr<application::IArtifactExporter> artifactExporter);

        [[nodiscard]] bool Navigate(winrt::hstring const& routeTag);

    private:
        [[nodiscard]] bool NavigateToOverview();

        winrt::Microsoft::UI::Xaml::Controls::Frame m_frame{ nullptr };
        winrt::Microsoft::UI::WindowId m_windowId{};
        std::shared_ptr<application::ITargetFilePicker> m_picker;
        std::shared_ptr<application::IUnpackEngineClient> m_engineClient;
        std::shared_ptr<application::IArtifactExporter> m_artifactExporter;
        winrt::hstring m_currentRoute;
    };
}
