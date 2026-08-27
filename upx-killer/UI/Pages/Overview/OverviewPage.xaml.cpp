#include "pch.h"
#include "UI/Pages/Overview/OverviewPage.xaml.h"
#if __has_include("OverviewPage.g.cpp")
#include "OverviewPage.g.cpp"
#endif

#include "UI/ViewModels/OverviewViewModel.h"

#include <winrt/Microsoft.UI.Xaml.Automation.h>
#include <winrt/Microsoft.UI.Xaml.Navigation.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>
#include <winrt/Windows.ApplicationModel.DataTransfer.h>
#include <winrt/Windows.Storage.h>

namespace winrt::upx_killer::implementation
{
    OverviewPage::OverviewPage()
        : m_viewModel(winrt::make<implementation::OverviewViewModel>())
    {
        InitializeComponent();

        auto const resources = winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader{};
        winrt::Microsoft::UI::Xaml::Automation::AutomationProperties::SetName(
            SelectTargetButton(), resources.GetString(L"SelectTargetAutomationName"));
        winrt::Microsoft::UI::Xaml::Automation::AutomationProperties::SetName(
            TargetPathTextBox(), resources.GetString(L"TargetPathAutomationName"));
    }

    winrt::upx_killer::OverviewViewModel OverviewPage::ViewModel() const
    {
        return m_viewModel;
    }

    void OverviewPage::OnNavigatedTo(
        winrt::Microsoft::UI::Xaml::Navigation::NavigationEventArgs const& args)
    {
        auto const viewModel =
            args.Parameter().try_as<winrt::upx_killer::OverviewViewModel>();

        if (!viewModel)
        {
            return;
        }

        m_viewModel = viewModel;
    }

    void OverviewPage::OnTargetDragOver(
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& sender,
        winrt::Microsoft::UI::Xaml::DragEventArgs const& args)
    {
        using namespace winrt::Windows::ApplicationModel::DataTransfer;

        if (args.DataView().Contains(StandardDataFormats::StorageItems()))
        {
            args.AcceptedOperation(DataPackageOperation::Copy);
            args.Handled(true);
        }
    }

    void OverviewPage::OnTargetDrop(
        [[maybe_unused]] winrt::Windows::Foundation::IInspectable const& sender,
        winrt::Microsoft::UI::Xaml::DragEventArgs const& args)
    {
        LoadDroppedFileAsync(args.DataView());
        args.Handled(true);
    }

    winrt::fire_and_forget OverviewPage::LoadDroppedFileAsync(
        winrt::Windows::ApplicationModel::DataTransfer::DataPackageView const& dataView)
    {
        auto lifetime = get_strong();
        auto const viewModel = winrt::get_self<implementation::OverviewViewModel>(m_viewModel);

        try
        {
            using winrt::Windows::ApplicationModel::DataTransfer::StandardDataFormats;
            using winrt::Windows::Storage::StorageFile;

            if (!dataView.Contains(StandardDataFormats::StorageItems()))
            {
                viewModel->ReportInvalidDrop();
                co_return;
            }

            auto const items = co_await dataView.GetStorageItemsAsync();
            if (items.Size() != 1)
            {
                viewModel->ReportInvalidDrop();
                co_return;
            }

            auto const file = items.GetAt(0).try_as<StorageFile>();
            if (!file)
            {
                viewModel->ReportInvalidDrop();
                co_return;
            }

            viewModel->LoadTargetPath(file.Path());
        }
        catch (...)
        {
            viewModel->ReportDropFailure();
        }
    }
}
