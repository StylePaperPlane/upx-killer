#pragma once

#include "Application/Updates/UpdateCheckWorkflow.h"

#include <string>

#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>
#include <winrt/base.h>

namespace upx_killer::ui::presentation {
class UpdateCheckPresentation final {
 public:
  [[nodiscard]] static winrt::hstring CurrentVersion(
      std::string const& version);

  [[nodiscard]] static winrt::hstring Result(
      winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader const&
          resources,
      application::UpdateCheckResult const& result);
};
}
