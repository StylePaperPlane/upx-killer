#pragma once

#include <functional>
#include <utility>

#include <winrt/Microsoft.UI.Xaml.Input.h>
#include <winrt/Windows.Foundation.h>

namespace upx_killer::ui
{
    struct RelayCommand : winrt::implements<RelayCommand, winrt::Microsoft::UI::Xaml::Input::ICommand>
    {
        using ExecuteHandler = std::function<void()>;
        using CanExecuteHandler = std::function<bool()>;

        RelayCommand(ExecuteHandler execute, CanExecuteHandler canExecute)
            : m_execute(std::move(execute)), m_canExecute(std::move(canExecute))
        {
        }

        winrt::event_token CanExecuteChanged(
            winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable> const& handler)
        {
            return m_canExecuteChanged.add(handler);
        }

        void CanExecuteChanged(winrt::event_token const& token) noexcept
        {
            m_canExecuteChanged.remove(token);
        }

        [[nodiscard]] bool CanExecute(
            [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& parameter) const
        {
            return !m_canExecute || m_canExecute();
        }

        void Execute([[maybe_unused]] winrt::Windows::Foundation::IInspectable const& parameter)
        {
            if (CanExecute(nullptr) && m_execute)
            {
                m_execute();
            }
        }

        void RaiseCanExecuteChanged()
        {
            m_canExecuteChanged(nullptr, nullptr);
        }

    private:
        ExecuteHandler m_execute;
        CanExecuteHandler m_canExecute;
        winrt::event<winrt::Windows::Foundation::EventHandler<winrt::Windows::Foundation::IInspectable>> m_canExecuteChanged;
    };
}
