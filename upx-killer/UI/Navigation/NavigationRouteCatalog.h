#pragma once

#include "Application/TargetSelection/TargetSelectionWorkflow.h"
#include "Application/TemporaryFiles/ITemporaryArtifactWorkspace.h"
#include "Application/TemporaryFiles/ITemporaryFolderPicker.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"
#include "Application/Unpacking/IArtifactExporter.h"
#include "Application/Unpacking/IUnpackEngineClient.h"
#include "UI/Navigation/NavigationRouter.h"

#include <cstdint>
#include <memory>
#include <vector>

#include <winrt/Microsoft.UI.h>

namespace upx_killer::ui {
struct NavigationRouteDependencies {
  winrt::Microsoft::UI::WindowId windowId{};
  std::uintptr_t ownerWindowHandle{};
  std::shared_ptr<application::ITargetFilePicker> picker;
  std::shared_ptr<application::IUnpackEngineClient> engineClient;
  std::shared_ptr<application::ITemporaryArtifactWorkspace> workspace;
  std::shared_ptr<application::IArtifactExporter> artifactExporter;
  std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore;
  std::shared_ptr<application::ITemporaryFolderPicker> folderPicker;
};

class NavigationRouteCatalog final {
 public:
  [[nodiscard]] static std::vector<NavigationRouteRegistration> Create(
      NavigationRouteDependencies dependencies);
};
}
