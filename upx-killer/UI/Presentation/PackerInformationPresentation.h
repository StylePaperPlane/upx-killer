#pragma once

#include "Core/BinaryInspection/TargetBinaryInspector.h"

#include <winrt/base.h>
#include <winrt/Microsoft.Windows.ApplicationModel.Resources.h>

namespace upx_killer::ui::presentation {
class PackerInformationPresentation final {
 public:
  [[nodiscard]] static winrt::hstring Format(
      core::UpxPackerInformation const& information,
      winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader const& resources);
};
}  // namespace upx_killer::ui::presentation
