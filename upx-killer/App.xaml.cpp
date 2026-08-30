#include "pch.h"
#include "App.xaml.h"
#include "Infrastructure/Storage/TargetFilePicker.h"
#include "Infrastructure/EngineHost/EngineHostClient.h"
#include "Infrastructure/Storage/ArtifactFileExporter.h"
#include "Infrastructure/Settings/LocalTemporaryFileSettingsStore.h"
#include "Infrastructure/Storage/TemporaryFolderPicker.h"
#include "UI/Windows/MainWindow/MainWindow.xaml.h"

#include <memory>

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
  get_self<MainWindow>(mainWindow)
      ->InitializeShell(std::make_shared<::upx_killer::infrastructure::TargetFilePicker>(),
                        std::make_shared<::upx_killer::infrastructure::EngineHostClient>(
                            ::upx_killer::infrastructure::EngineHostClient::AdjacentHostPath(),
                            temporaryFileSettings),
                        std::make_shared<::upx_killer::infrastructure::ArtifactFileExporter>(
                            temporaryFileSettings),
                        temporaryFileSettings,
                        std::make_shared<::upx_killer::infrastructure::TemporaryFolderPicker>());

  window = mainWindow;
  window.Activate();
}
}
