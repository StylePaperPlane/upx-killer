#include "Infrastructure/Windows/Storage/WindowsArtifactStore.h"

#include <Windows.h>

#include <fstream>

namespace {
std::filesystem::path TemporaryArtifactPath(
    std::filesystem::path const& finalPath) {
  return finalPath.parent_path() /
         (finalPath.stem().wstring() + L".publishing" +
          finalPath.extension().wstring());
}
}

namespace upx_killer::engine::storage {
application::artifacts::ArtifactStageResult WindowsArtifactStore::Stage(
    std::filesystem::path const& finalPath,
    std::span<std::byte const> bytes) const noexcept {
  try {
    if (finalPath.empty() || bytes.empty())
      return {std::nullopt, ERROR_INVALID_PARAMETER};
    std::error_code error;
    std::filesystem::create_directories(finalPath.parent_path(), error);
    if (error) return {std::nullopt, static_cast<std::uint32_t>(error.value())};
    auto temporaryPath = TemporaryArtifactPath(finalPath);
    std::ofstream stream(temporaryPath, std::ios::binary | std::ios::trunc);
    if (!stream) return {std::nullopt, ERROR_WRITE_FAULT};
    stream.write(reinterpret_cast<char const*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    if (!stream) {
      stream.close();
      std::filesystem::remove(temporaryPath, error);
      return {std::nullopt, ERROR_WRITE_FAULT};
    }
    stream.close();
    return {std::move(temporaryPath), 0};
  } catch (...) {
    return {std::nullopt, ERROR_WRITE_FAULT};
  }
}

std::uint32_t WindowsArtifactStore::Promote(
    std::filesystem::path const& temporaryPath,
    std::filesystem::path const& finalPath) const noexcept {
  if (MoveFileExW(temporaryPath.c_str(), finalPath.c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    return 0;
  return GetLastError();
}

void WindowsArtifactStore::Remove(std::filesystem::path const& path) const noexcept {
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}
}
