#include "pch.h"
#include "UI/Windows/MainWindow/MainWindow.xaml.h"

#if __has_include("MainWindow.g.cpp")
#include "MainWindow.g.cpp"
#endif

#include "UI/Navigation/NavigationPaneController.h"
#include "UI/Navigation/NavigationRouteCatalog.h"
#include "UI/Navigation/NavigationRouter.h"

#include <microsoft.ui.xaml.window.h>
#include <winrt/Microsoft.UI.Windowing.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.h>

namespace {
constexpr double InitialWindowWidthDips = 960.0;
constexpr double InitialWindowHeightDips = 520.0;
constexpr double MinimumWindowWidthDips = 640.0;
constexpr double MinimumWindowHeightDips = 420.0;
constexpr wchar_t OverviewRoute[] = L"overview";
}

namespace winrt::upx_killer::implementation {
MainWindow::MainWindow() {
  InitializeComponent();

  auto const resources = winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader{};

  Title(resources.GetString(L"MainWindowTitle"));

  auto const nativeWindow = try_as<::IWindowNative>();
  if (!nativeWindow) {
    return;
  }

  HWND windowHandle{};
  winrt::check_hresult(nativeWindow->get_WindowHandle(&windowHandle));
  m_windowHandle = reinterpret_cast<std::uintptr_t>(windowHandle);

  auto const scale = static_cast<double>(GetDpiForWindow(windowHandle)) / 96.0;

  auto const toPhysicalPixels = [scale](double dips) {
    return static_cast<std::int32_t>(dips * scale + 0.5);
  };

  auto const appWindow = AppWindow();

  if (auto const presenter =
          appWindow.Presenter().try_as<winrt::Microsoft::UI::Windowing::OverlappedPresenter>()) {
    presenter.PreferredMinimumWidth(
        winrt::box_value(toPhysicalPixels(MinimumWindowWidthDips))
            .as<winrt::Windows::Foundation::IReference<std::int32_t>>());

    presenter.PreferredMinimumHeight(
        winrt::box_value(toPhysicalPixels(MinimumWindowHeightDips))
            .as<winrt::Windows::Foundation::IReference<std::int32_t>>());
  }

  appWindow.Resize(winrt::Windows::Graphics::SizeInt32{toPhysicalPixels(InitialWindowWidthDips),
                                                       toPhysicalPixels(InitialWindowHeightDips)});

  m_navigationPaneController = std::make_unique<::upx_killer::ui::NavigationPaneController>(
      RootNavigationView(), reinterpret_cast<std::uintptr_t>(windowHandle));
}

MainWindow::~MainWindow() = default;

void MainWindow::InitializeShell(
    std::shared_ptr<::upx_killer::application::ITargetFilePicker> picker,
    std::shared_ptr<::upx_killer::application::IUnpackEngineClient> engineClient,
    std::shared_ptr<::upx_killer::application::ITemporaryArtifactWorkspace> workspace,
    std::shared_ptr<::upx_killer::application::IArtifactExporter> artifactExporter,
    std::shared_ptr<::upx_killer::application::ITemporaryFileSettingsStore> settingsStore,
    std::shared_ptr<::upx_killer::application::ITemporaryFolderPicker> folderPicker,
    std::shared_ptr<::upx_killer::application::IWslRuntimeSettingsStore> wslSettingsStore,
    std::shared_ptr<::upx_killer::application::IWslDistributionCatalog> wslDistributionCatalog) {
  if (m_navigationRouter) {
    return;
  }

  m_navigationRouter = std::make_unique<::upx_killer::ui::NavigationRouter>(
      ContentFrame(), ::upx_killer::ui::NavigationRouteCatalog::Create(
                          {AppWindow().Id(), m_windowHandle, std::move(picker),
                           std::move(engineClient), std::move(workspace),
                           std::move(artifactExporter), std::move(settingsStore),
                           std::move(folderPicker), std::move(wslSettingsStore),
                           std::move(wslDistributionCatalog)}));

  RootNavigationView().SelectionChanged({this, &MainWindow::OnNavigationSelectionChanged});

  RootNavigationView().SelectedItem(OverviewNavigationItem());
  static_cast<void>(m_navigationRouter->Navigate(OverviewRoute));
}

void MainWindow::OnNavigationSelectionChanged(
    [[maybe_unused]] winrt::Microsoft::UI::Xaml::Controls::NavigationView const& sender,
    winrt::Microsoft::UI::Xaml::Controls::NavigationViewSelectionChangedEventArgs const& args) {
  if (!m_navigationRouter || args.IsSettingsSelected()) {
    return;
  }

  auto const selectedItem =
      args.SelectedItem().try_as<winrt::Microsoft::UI::Xaml::Controls::NavigationViewItem>();

  if (!selectedItem) {
    return;
  }

  auto const routeTag = winrt::unbox_value_or<winrt::hstring>(selectedItem.Tag(), L"");

  if (!routeTag.empty()) {
    static_cast<void>(m_navigationRouter->Navigate(routeTag));
  }
}
}
