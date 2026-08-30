#pragma once

#include "Core/BinaryInspection/TargetBinaryInspector.h"

#include <filesystem>
#include <memory>

#include <winrt/Microsoft.UI.h>
#include <winrt/Windows.Foundation.h>

namespace upx_killer::application {
class ITargetFilePicker {
 public:
  virtual ~ITargetFilePicker() = default;

  [[nodiscard]] virtual winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> PickAsync(
      winrt::Microsoft::UI::WindowId const& windowId) = 0;
};

class TargetSelectionWorkflow final {
 public:
  explicit TargetSelectionWorkflow(std::shared_ptr<ITargetFilePicker> picker);

  [[nodiscard]] winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> SelectPathAsync(
      winrt::Microsoft::UI::WindowId const& windowId) const;
  [[nodiscard]] core::InspectionResult Inspect(std::filesystem::path const& path) const noexcept;

 private:
  std::shared_ptr<ITargetFilePicker> m_picker;
};
}
