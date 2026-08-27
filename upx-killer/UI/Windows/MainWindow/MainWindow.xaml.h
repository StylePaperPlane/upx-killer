#pragma once

#define WINRT_FORCE_INCLUDE_MAINWINDOW_XAML_G_H
#include "MainWindow.g.h"

#include "Application/TargetSelection/TargetSelectionWorkflow.h"
#include "Application/Unpacking/IUnpackEngineClient.h"
#include "Application/Unpacking/IArtifactExporter.h"

#include <memory>

namespace upx_killer::ui
{
    class NavigationPaneController;
    class NavigationRouter;
}

namespace winrt::upx_killer::implementation
{
    struct MainWindow : MainWindowT<MainWindow>
    {
        MainWindow();
        ~MainWindow();

        void InitializeShell(
            std::shared_ptr<::upx_killer::application::ITargetFilePicker> picker,
            std::shared_ptr<::upx_killer::application::IUnpackEngineClient> engineClient,
            std::shared_ptr<::upx_killer::application::IArtifactExporter> artifactExporter);

    private:
        void OnNavigationSelectionChanged(
            winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
            winrt::Microsoft::UI::Xaml::Controls::NavigationViewSelectionChangedEventArgs const& args);

        std::unique_ptr<::upx_killer::ui::NavigationPaneController> m_navigationPaneController;
        std::unique_ptr<::upx_killer::ui::NavigationRouter> m_navigationRouter;
    };
}

namespace winrt::upx_killer::factory_implementation
{
    struct MainWindow : MainWindowT<MainWindow, implementation::MainWindow>
    {
    };
}
