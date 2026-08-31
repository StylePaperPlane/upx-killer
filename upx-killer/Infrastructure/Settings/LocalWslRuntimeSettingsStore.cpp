#include "pch.h"
#include "Infrastructure/Settings/LocalWslRuntimeSettingsStore.h"

#include "Infrastructure/Settings/LocalSettingsPath.h"

#include <Windows.h>

#include <array>

namespace {
constexpr wchar_t SettingsSection[] = L"WslRuntime";
constexpr wchar_t DistributionKey[] = L"Distribution";
}

namespace upx_killer::infrastructure {
LocalWslRuntimeSettingsStore::LocalWslRuntimeSettingsStore()
    : settingsFile_(LocalSettingsPath::Resolve()) {}

application::WslRuntimeSettings
LocalWslRuntimeSettingsStore::Load() const noexcept {
  std::scoped_lock lock{mutex_};
  std::array<wchar_t, 256> value{};
  auto const length = GetPrivateProfileStringW(
      SettingsSection, DistributionKey, L"", value.data(),
      static_cast<DWORD>(value.size()), settingsFile_.c_str());
  return {std::wstring{value.data(), length}};
}

bool LocalWslRuntimeSettingsStore::Save(
    application::WslRuntimeSettings const& settings) noexcept {
  std::scoped_lock lock{mutex_};
  try {
    std::filesystem::create_directories(settingsFile_.parent_path());
    return WritePrivateProfileStringW(SettingsSection, DistributionKey,
                                      settings.distribution.c_str(),
                                      settingsFile_.c_str()) != FALSE;
  } catch (...) {
    return false;
  }
}
}  // namespace upx_killer::infrastructure
