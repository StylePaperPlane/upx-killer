#include "pch.h"
#include "App.xaml.h"
#include "Infrastructure/Storage/TargetFilePicker.h"
#include "Infrastructure/EngineHost/EngineHostClient.h"
#include "Infrastructure/Storage/ArtifactFileExporter.h"
#include "Infrastructure/Settings/LocalTemporaryFileSettingsStore.h"
#include "Infrastructure/Settings/LocalWslRuntimeSettingsStore.h"
#include "Infrastructure/WSL/Discovery/WslDistributionCatalog.h"
#include "Infrastructure/Storage/TemporaryFolderPicker.h"
#include "Infrastructure/Storage/LocalTemporaryArtifactWorkspace.h"
#include "UI/Composition/ConfigurationRouteFactory.h"
#include "UI/Composition/OverviewRouteFactory.h"
#include "UI/Windows/MainWindow/MainWindow.xaml.h"

#include <microsoft.ui.xaml.window.h>
#include <memory>
#include <vector>

#include <winrt/Microsoft.UI.Windowing.h>

using namespace winrt;
using namespace Microsoft::UI::Xaml;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace winrt::upx_killer::implementation {
/// <summary>
/// Initializes the singleton application object.  This is the first line of authored code
/// executed, and as such is the logical equivalent of main() or WinMain().
/// </summary>
App::App() {
  // Xaml objects should not call InitializeComponent during construction.
  // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent

#if defined _DEBUG && !defined DISABLE_XAML_GENERATED_BREAK_ON_UNHANDLED_EXCEPTION
  UnhandledException([](IInspectable const&, UnhandledExceptionEventArgs const& e) {
    if (IsDebuggerPresent()) {
      auto errorMessage = e.Message();
      __debugbreak();
    }
  });
#endif
}

/// <summary>
/// Invoked when the application is launched.
/// </summary>
/// <param name="e">Details about the launch request and process.</param>
void App::OnLaunched([[maybe_unused]] LaunchActivatedEventArgs const& e) {
  auto const temporaryFileSettings =
      std::make_shared<::upx_killer::infrastructure::LocalTemporaryFileSettingsStore>();
  auto const mainWindow = make<MainWindow>();
  auto const wslSettings =
      std::make_shared<::upx_killer::infrastructure::LocalWslRuntimeSettingsStore>();
  auto const workspace =
      std::make_shared<::upx_killer::infrastructure::LocalTemporaryArtifactWorkspace>(
          temporaryFileSettings);
  auto const picker =
      std::make_shared<::upx_killer::infrastructure::TargetFilePicker>();
  auto const engineClient =
      std::make_shared<::upx_killer::infrastructure::EngineHostClient>(
          ::upx_killer::infrastructure::EngineHostClient::AdjacentHostPath(),
          wslSettings);
  auto const artifactExporter =
      std::make_shared<::upx_killer::infrastructure::ArtifactFileExporter>(
          temporaryFileSettings);
  auto const folderPicker =
      std::make_shared<::upx_killer::infrastructure::TemporaryFolderPicker>();
  auto const wslDistributionCatalog =
      std::make_shared<::upx_killer::infrastructure::WslDistributionCatalog>();

  auto const nativeWindow = mainWindow.as<::IWindowNative>();
  HWND ownerWindow{};
  winrt::check_hresult(nativeWindow->get_WindowHandle(&ownerWindow));
  auto const ownerWindowHandle = reinterpret_cast<std::uintptr_t>(ownerWindow);
  auto const windowId = mainWindow.AppWindow().Id();

  std::vector<::upx_killer::ui::NavigationRouteRegistration> routes;
  routes.emplace_back(
      ::upx_killer::ui::composition::OverviewRouteFactory::Create(
          {windowId, picker, engineClient, workspace, artifactExporter,
           temporaryFileSettings}));
  routes.emplace_back(
      ::upx_killer::ui::composition::ConfigurationRouteFactory::Create(
          {ownerWindowHandle, temporaryFileSettings, folderPicker, wslSettings,
           wslDistributionCatalog}));
  get_self<MainWindow>(mainWindow)->InitializeShell(std::move(routes));

  window = mainWindow;
  window.Activate();
}
}
