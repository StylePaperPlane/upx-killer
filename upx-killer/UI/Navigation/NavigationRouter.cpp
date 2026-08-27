#include "pch.h"
#include "UI/Navigation/NavigationRouter.h"

#include "UI/ViewModels/OverviewViewModel.h"

#include <stdexcept>
#include <utility>

#include <winrt/Windows.UI.Xaml.Interop.h>

namespace
{
    constexpr wchar_t OverviewRoute[] = L"overview";
}

namespace upx_killer::ui
{
    NavigationRouter::NavigationRouter(
        winrt::Microsoft::UI::Xaml::Controls::Frame const& frame,
        winrt::Microsoft::UI::WindowId const& windowId,
        std::shared_ptr<application::ITargetFilePicker> picker,
        std::shared_ptr<application::IUnpackEngineClient> engineClient,
        std::shared_ptr<application::IArtifactExporter> artifactExporter)
        : m_frame(frame),
          m_windowId(windowId),
          m_picker(std::move(picker)),
          m_engineClient(std::move(engineClient)),
          m_artifactExporter(std::move(artifactExporter))
    {
        if (!m_frame)
        {
            throw std::invalid_argument("frame");
        }

        if (!m_picker)
        {
            throw std::invalid_argument("picker");
        }

        if (!m_engineClient)
        {
            throw std::invalid_argument("engineClient");
        }
        if (!m_artifactExporter)
        {
            throw std::invalid_argument("artifactExporter");
        }
    }

    bool NavigationRouter::Navigate(winrt::hstring const& routeTag)
    {
        if (routeTag == m_currentRoute && m_frame.Content())
        {
            return true;
        }

        if (routeTag == OverviewRoute)
        {
            return NavigateToOverview();
        }

        return false;
    }

    bool NavigationRouter::NavigateToOverview()
    {
        auto const viewModel =
            winrt::make<winrt::upx_killer::implementation::OverviewViewModel>();

        winrt::get_self<winrt::upx_killer::implementation::OverviewViewModel>(viewModel)
            ->Initialize(m_windowId, m_picker, m_engineClient, m_artifactExporter);

        bool const navigated =
            m_frame.Navigate(
                winrt::xaml_typename<winrt::upx_killer::OverviewPage>(),
                viewModel);

        if (navigated)
        {
            m_currentRoute = OverviewRoute;
        }

        return navigated;
    }
}
