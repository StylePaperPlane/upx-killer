#pragma once

#define WINRT_FORCE_INCLUDE_OVERVIEWPAGE_XAML_G_H
#include "OverviewPage.g.h"

#include <winrt/Microsoft.UI.Xaml.Navigation.h>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>

namespace winrt::upx_killer::implementation
{
    struct OverviewPage : OverviewPageT<OverviewPage>
    {
        OverviewPage();

        winrt::upx_killer::OverviewViewModel ViewModel() const;
        void OnNavigatedTo(
            winrt::Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args);
        void OnTargetDragOver(
            winrt::Windows::Foundation::IInspectable const& sender,
            winrt::Microsoft::UI::Xaml::DragEventArgs const& args);
        void OnTargetDrop(
            winrt::Windows::Foundation::IInspectable const& sender,
            winrt::Microsoft::UI::Xaml::DragEventArgs const& args);

    private:
        winrt::fire_and_forget LoadDroppedFileAsync(
            winrt::Windows::ApplicationModel::DataTransfer::DataPackageView const& dataView);

        winrt::upx_killer::OverviewViewModel m_viewModel{ nullptr };
    };
}

namespace winrt::upx_killer::factory_implementation
{
    struct OverviewPage : OverviewPageT<OverviewPage, implementation::OverviewPage>
    {
    };
}
