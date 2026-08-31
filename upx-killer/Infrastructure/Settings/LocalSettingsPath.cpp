#include "pch.h"
#include "Infrastructure/Settings/LocalSettingsPath.h"

#include <ShlObj.h>

namespace upx_killer::infrastructure {
std::filesystem::path LocalSettingsPath::Resolve() noexcept {
  PWSTR localAppDataRaw{};
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT,
                                     nullptr, &localAppDataRaw))) {
    std::filesystem::path const localAppData{localAppDataRaw};
    CoTaskMemFree(localAppDataRaw);
    return localAppData / L"upx-killer" / L"settings.ini";
  }
  try {
    return std::filesystem::temp_directory_path() / L"upx-killer" /
           L"settings.ini";
  } catch (...) {
    return L"settings.ini";
  }
}
}  // namespace upx_killer::infrastructure
