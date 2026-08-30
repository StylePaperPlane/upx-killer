#pragma once

#include "Application/TemporaryFiles/TemporaryFileSettings.h"

#include <filesystem>
#include <mutex>

namespace upx_killer::infrastructure {
class LocalTemporaryFileSettingsStore final : public application::ITemporaryFileSettingsStore {
 public:
  LocalTemporaryFileSettingsStore();

  [[nodiscard]] application::TemporaryFileSettings Load() const noexcept override;
  [[nodiscard]] bool Save(application::TemporaryFileSettings const& settings) noexcept override;

 private:
  [[nodiscard]] static std::filesystem::path DefaultTemporaryDirectory() noexcept;
  [[nodiscard]] static std::filesystem::path SettingsFilePath() noexcept;

  std::filesystem::path m_settingsFile;
  mutable std::mutex m_mutex;
};
}
