#pragma once

#include "Application/TargetSelection/TargetSelectionWorkflow.h"

namespace upx_killer::infrastructure {

class TargetFilePicker final : public application::ITargetFilePicker {
 public:
  [[nodiscard]] winrt::Windows::Foundation::IAsyncOperation<winrt::hstring> PickAsync(
      winrt::Microsoft::UI::WindowId const& windowId) override;
};

}
