#include "pch.h"
#include "Application/TargetSelection/TargetSelectionWorkflow.h"

#include <stdexcept>
#include <utility>

namespace upx_killer::application {
TargetSelectionWorkflow::TargetSelectionWorkflow(std::shared_ptr<ITargetFilePicker> picker)
    : m_picker(std::move(picker)) {
  if (!m_picker) {
    throw std::invalid_argument("picker");
  }
}

winrt::Windows::Foundation::IAsyncOperation<winrt::hstring>
TargetSelectionWorkflow::SelectPathAsync(winrt::Microsoft::UI::WindowId const& windowId) const {
  co_return co_await m_picker->PickAsync(windowId);
}

core::InspectionResult TargetSelectionWorkflow::Inspect(
    std::filesystem::path const& path) const noexcept {
  return core::TargetBinaryInspector::Inspect(path);
}
}
