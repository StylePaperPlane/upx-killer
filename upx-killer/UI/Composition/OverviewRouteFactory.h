#pragma once

#include "Application/TargetSelection/TargetSelectionWorkflow.h"
#include "Application/TemporaryFiles/ITemporaryArtifactWorkspace.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"
#include "Application/Unpacking/IArtifactExporter.h"
#include "Application/Unpacking/IUnpackEngineClient.h"
#include "UI/Navigation/NavigationRouter.h"

#include <memory>

#include <winrt/Microsoft.UI.h>

namespace upx_killer::ui::composition {

struct OverviewRouteDependencies {
  winrt::Microsoft::UI::WindowId windowId{};
  std::shared_ptr<application::ITargetFilePicker> picker;
  std::shared_ptr<application::IUnpackEngineClient> engineClient;
  std::shared_ptr<application::ITemporaryArtifactWorkspace> workspace;
  std::shared_ptr<application::IArtifactExporter> artifactExporter;
  std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore;
};

class OverviewRouteFactory final {
 public:
  [[nodiscard]] static NavigationRouteRegistration Create(
      OverviewRouteDependencies dependencies);
};

}  // namespace upx_killer::ui::composition
