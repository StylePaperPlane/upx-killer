#pragma once

#include "Application/Runtime/WslRuntimeSettings.h"

#include <filesystem>
#include <mutex>

namespace upx_killer::infrastructure {

class LocalWslRuntimeSettingsStore final
    : public application::IWslRuntimeSettingsStore {
 public:
  LocalWslRuntimeSettingsStore();
  [[nodiscard]] application::WslRuntimeSettings Load() const noexcept override;
  [[nodiscard]] bool Save(
      application::WslRuntimeSettings const& settings) noexcept override;

 private:
  std::filesystem::path settingsFile_;
  mutable std::mutex mutex_;
};

}  // namespace upx_killer::infrastructure
