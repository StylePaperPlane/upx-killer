#include "pch.h"
#include "UI/Navigation/NavigationPaneController.h"

#include <chrono>
#include <stdexcept>

namespace upx_killer::ui
{
    NavigationPaneController::NavigationPaneController(
        winrt::Microsoft::UI::Xaml::Controls::NavigationView const& navigationView,
        std::uintptr_t windowHandle)
        : m_navigationView(navigationView),
          m_windowHandle(windowHandle)
    {
        if (!m_navigationView)
        {
            throw std::invalid_argument("navigationView");
        }

        if (!m_windowHandle)
        {
            throw std::invalid_argument("windowHandle");
        }

        m_timer.Interval(std::chrono::milliseconds{ 100 });
        m_loadedToken =
            m_navigationView.Loaded({ this, &NavigationPaneController::OnLoaded });
        m_unloadedToken =
            m_navigationView.Unloaded({ this, &NavigationPaneController::OnUnloaded });
        m_paneOpeningToken =
            m_navigationView.PaneOpening({ this, &NavigationPaneController::OnPaneOpening });
        m_paneClosingToken =
            m_navigationView.PaneClosing({ this, &NavigationPaneController::OnPaneClosing });
        m_timerTickToken =
            m_timer.Tick({ this, &NavigationPaneController::OnTimerTick });
    }

    NavigationPaneController::~NavigationPaneController()
    {
        m_timer.Stop();
        m_timer.Tick(m_timerTickToken);

        if (m_navigationView)
        {
            m_navigationView.Loaded(m_loadedToken);
            m_navigationView.Unloaded(m_unloadedToken);
            m_navigationView.PaneOpening(m_paneOpeningToken);
            m_navigationView.PaneClosing(m_paneClosingToken);
        }
    }

    void NavigationPaneController::OnLoaded(
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& sender,
        [[maybe_unused]] winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args)
    {
        m_timer.Start();
    }

    void NavigationPaneController::OnUnloaded(
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& sender,
        [[maybe_unused]] winrt::Microsoft::UI::Xaml::RoutedEventArgs const& args)
    {
        m_timer.Stop();
    }

    void NavigationPaneController::OnPaneOpening(
        [[maybe_unused]] winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& args)
    {
        if (m_internalPaneRequest == true)
        {
            m_internalPaneRequest.reset();
            return;
        }

        m_internalPaneRequest.reset();
        m_manualCloseSuppressed = false;
        m_pointerObservedInsideOpenPane =
            IsPointerInsidePane(m_navigationView.OpenPaneLength());
    }

    void NavigationPaneController::OnPaneClosing(
        [[maybe_unused]] winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
        [[maybe_unused]]
        winrt::Microsoft::UI::Xaml::Controls::NavigationViewPaneClosingEventArgs const& args)
    {
        if (m_internalPaneRequest == false)
        {
            m_internalPaneRequest.reset();
            return;
        }

        m_internalPaneRequest.reset();
        m_manualCloseSuppressed = true;
        m_pointerObservedInsideOpenPane = false;
    }

    void NavigationPaneController::OnTimerTick(
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& sender,
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& args)
    {
        if (m_navigationView.IsPaneOpen())
        {
            if (IsPointerInsidePane(m_navigationView.OpenPaneLength()))
            {
                m_pointerObservedInsideOpenPane = true;
                return;
            }

            if (m_pointerObservedInsideOpenPane)
            {
                SetPaneOpen(false);
            }

            return;
        }

        bool const pointerInsideCompactPane =
            IsPointerInsidePane(m_navigationView.CompactPaneLength());

        if (m_manualCloseSuppressed)
        {
            if (!pointerInsideCompactPane)
            {
                m_manualCloseSuppressed = false;
            }

            return;
        }

        if (pointerInsideCompactPane)
        {
            SetPaneOpen(true);
            m_pointerObservedInsideOpenPane = true;
        }
    }

    bool NavigationPaneController::IsPointerInsidePane(double paneWidthDips) const noexcept
    {
        auto const windowHandle = reinterpret_cast<HWND>(m_windowHandle);
        POINT cursorPosition{};
        RECT clientBounds{};

        if (!windowHandle ||
            !GetCursorPos(&cursorPosition) ||
            !ScreenToClient(windowHandle, &cursorPosition) ||
            !GetClientRect(windowHandle, &clientBounds))
        {
            return false;
        }

        auto const dpi = GetDpiForWindow(windowHandle);
        auto const scale = dpi == 0 ? 1.0 : static_cast<double>(dpi) / 96.0;
        auto const paneWidthPixels =
            static_cast<LONG>(paneWidthDips * scale + 0.5);

        return cursorPosition.x >= clientBounds.left &&
               cursorPosition.x < paneWidthPixels &&
               cursorPosition.y >= clientBounds.top &&
               cursorPosition.y < clientBounds.bottom;
    }

    void NavigationPaneController::SetPaneOpen(bool isOpen)
    {
        if (m_navigationView.IsPaneOpen() == isOpen)
        {
            return;
        }

        m_internalPaneRequest = isOpen;
        m_navigationView.IsPaneOpen(isOpen);

        if (!isOpen)
        {
            m_pointerObservedInsideOpenPane = false;
        }
    }
}
