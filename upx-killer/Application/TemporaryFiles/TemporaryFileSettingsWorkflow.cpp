#include "pch.h"
#include "Application/TemporaryFiles/TemporaryFileSettingsWorkflow.h"

#include <stdexcept>
#include <utility>

namespace upx_killer::application {
TemporaryFileSettingsWorkflow::TemporaryFileSettingsWorkflow(
    std::shared_ptr<ITemporaryFileSettingsStore> store,
    std::shared_ptr<ITemporaryFolderPicker> folderPicker)
    : m_store(std::move(store)), m_folderPicker(std::move(folderPicker)) {
  if (!m_store) throw std::invalid_argument("store");
  if (!m_folderPicker) throw std::invalid_argument("folderPicker");
}

TemporaryFileSettings TemporaryFileSettingsWorkflow::Load() const noexcept {
  return m_store->Load();
}

winrt::Windows::Foundation::IAsyncOperation<bool>
TemporaryFileSettingsWorkflow::SelectDirectoryAsync(std::uintptr_t ownerWindowHandle) {
  auto const selected = co_await m_folderPicker->PickAsync(ownerWindowHandle);
  if (selected.empty()) co_return false;

  auto settings = m_store->Load();
  settings.directory = std::filesystem::path{selected.c_str()};
  co_return m_store->Save(settings);
}

bool TemporaryFileSettingsWorkflow::SetDeleteAfterExport(bool enabled) noexcept {
  auto settings = m_store->Load();
  settings.deleteAfterExport = enabled;
  return m_store->Save(settings);
}
}
