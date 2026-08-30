#include "pch.h"
#include "Infrastructure/Settings/LocalTemporaryFileSettingsStore.h"

#include <ShlObj.h>

#include <array>

#pragma comment(lib, "Shell32.lib")

namespace {
constexpr wchar_t SettingsSection[] = L"TemporaryFiles";
constexpr wchar_t DirectoryKey[] = L"Directory";
constexpr wchar_t DeleteAfterExportKey[] = L"DeleteAfterExport";
}

namespace upx_killer::infrastructure {
LocalTemporaryFileSettingsStore::LocalTemporaryFileSettingsStore()
    : m_settingsFile(SettingsFilePath()) {}

application::TemporaryFileSettings LocalTemporaryFileSettingsStore::Load() const noexcept {
  std::scoped_lock lock{m_mutex};
  application::TemporaryFileSettings settings{};
  settings.directory = DefaultTemporaryDirectory();

  try {
    std::array<wchar_t, 32768> directory{};
    auto const length =
        GetPrivateProfileStringW(SettingsSection, DirectoryKey, L"", directory.data(),
                                 static_cast<DWORD>(directory.size()), m_settingsFile.c_str());
    if (length != 0) settings.directory = std::filesystem::path{directory.data()};

    settings.deleteAfterExport = GetPrivateProfileIntW(SettingsSection, DeleteAfterExportKey, 1,
                                                       m_settingsFile.c_str()) != 0;
  } catch (...) {
  }

  return settings;
}

bool LocalTemporaryFileSettingsStore::Save(
    application::TemporaryFileSettings const& settings) noexcept {
  std::scoped_lock lock{m_mutex};
  try {
    if (settings.directory.empty()) return false;
    std::filesystem::create_directories(m_settingsFile.parent_path());
    if (!WritePrivateProfileStringW(SettingsSection, DirectoryKey, settings.directory.c_str(),
                                    m_settingsFile.c_str()))
      return false;

    return WritePrivateProfileStringW(SettingsSection, DeleteAfterExportKey,
                                      settings.deleteAfterExport ? L"1" : L"0",
                                      m_settingsFile.c_str()) != FALSE;
  } catch (...) {
    return false;
  }
}

std::filesystem::path LocalTemporaryFileSettingsStore::DefaultTemporaryDirectory() noexcept {
  try {
    return std::filesystem::temp_directory_path() / L"upx-killer";
  } catch (...) {
    return L".";
  }
}

std::filesystem::path LocalTemporaryFileSettingsStore::SettingsFilePath() noexcept {
  PWSTR localAppDataRaw{};
  if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr,
                                     &localAppDataRaw))) {
    std::filesystem::path const localAppData{localAppDataRaw};
    CoTaskMemFree(localAppDataRaw);
    return localAppData / L"upx-killer" / L"settings.ini";
  }

  return DefaultTemporaryDirectory() / L"settings.ini";
}
}
