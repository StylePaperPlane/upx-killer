#pragma once

#include <string>
#include <vector>

namespace upx_killer::application {

struct WslRuntimeSettings {
  std::wstring distribution;
};

struct WslDistributionInfo {
  std::wstring name;
  bool isDefault{};
  bool isWsl2{};
};

class IWslRuntimeSettingsStore {
 public:
  virtual ~IWslRuntimeSettingsStore() = default;
  [[nodiscard]] virtual WslRuntimeSettings Load() const noexcept = 0;
  [[nodiscard]] virtual bool Save(WslRuntimeSettings const& settings) noexcept = 0;
};

class IWslDistributionCatalog {
 public:
  virtual ~IWslDistributionCatalog() = default;
  [[nodiscard]] virtual std::vector<WslDistributionInfo> List() const noexcept = 0;
};

}  // namespace upx_killer::application
