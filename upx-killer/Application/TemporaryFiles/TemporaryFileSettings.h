#pragma once

#include <filesystem>

namespace upx_killer::application {
struct TemporaryFileSettings {
  std::filesystem::path directory;
  bool deleteAfterExport{true};
};

class ITemporaryFileSettingsStore {
 public:
  virtual ~ITemporaryFileSettingsStore() = default;
  [[nodiscard]] virtual TemporaryFileSettings Load() const noexcept = 0;
  [[nodiscard]] virtual bool Save(TemporaryFileSettings const& settings) noexcept = 0;
};
}
