#pragma once

#include <cstdint>
#include <optional>

#include <winrt/Microsoft.UI.Xaml.h>
#include <winrt/Microsoft.UI.Xaml.Controls.h>

namespace upx_killer::ui
{
    class NavigationPaneController final
    {
    public:
        NavigationPaneController(
            winrt::Microsoft::UI::Xaml::Controls::NavigationView const& navigationView,
            std::uintptr_t windowHandle);
        ~NavigationPaneController();

        NavigationPaneController(NavigationPaneController const&) = delete;
        NavigationPaneController& operator=(NavigationPaneController const&) = delete;

    private:
        void OnLoaded(
            winrt::Windows::Foundation::IInspectable const& sender,
            winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnUnloaded(
            winrt::Windows::Foundation::IInspectable const& sender,
            winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args);
        void OnPaneOpening(
            winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
            winrt::Windows::Foundation::IInspectable const& args);
        void OnPaneClosing(
            winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
            winrt::Microsoft::UI::Xaml::Controls::NavigationViewPaneClosingEventArgs const& args);
        void OnTimerTick(
            winrt::Windows::Foundation::IInspectable const& sender,
            winrt::Windows::Foundation::IInspectable const& args);

        [[nodiscard]] bool IsPointerInsidePane(double paneWidthDips) const noexcept;
        void SetPaneOpen(bool isOpen);

        winrt::Microsoft::UI::Xaml::Controls::NavigationView m_navigationView{ nullptr };
        winrt::Microsoft::UI::Xaml::DispatcherTimer m_timer;
        std::uintptr_t m_windowHandle{};
        winrt::event_token m_loadedToken{};
        winrt::event_token m_unloadedToken{};
        winrt::event_token m_paneOpeningToken{};
        winrt::event_token m_paneClosingToken{};
        winrt::event_token m_timerTickToken{};
        std::optional<bool> m_internalPaneRequest;
        bool m_manualCloseSuppressed{};
        bool m_pointerObservedInsideOpenPane{};
    };
}
