#include "Infrastructure/Linux/Storage/LinuxArtifactStore.h"

#include <sys/stat.h>

#include <cerrno>
#include <fstream>

namespace {
std::filesystem::path TemporaryArtifactPath(
    std::filesystem::path const& finalPath) {
  auto path = finalPath;
  path += ".part";
  return path;
}
}  // namespace

namespace upx_killer::elf_host::storage {
engine::application::artifacts::ArtifactStageResult LinuxArtifactStore::Stage(
    std::filesystem::path const& finalPath,
    std::span<std::byte const> bytes) const noexcept {
  try {
    if (finalPath.empty() || bytes.empty())
      return {std::nullopt, static_cast<std::uint32_t>(EINVAL)};
    std::error_code error;
    std::filesystem::create_directories(finalPath.parent_path(), error);
    if (error) return {std::nullopt, static_cast<std::uint32_t>(error.value())};
    auto temporaryPath = TemporaryArtifactPath(finalPath);
    std::ofstream stream(temporaryPath, std::ios::binary | std::ios::trunc);
    if (!stream)
      return {std::nullopt, static_cast<std::uint32_t>(errno)};
    stream.write(reinterpret_cast<char const*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
    stream.close();
    if (!stream || chmod(temporaryPath.c_str(), 0700) != 0) {
      auto const native = static_cast<std::uint32_t>(errno);
      std::filesystem::remove(temporaryPath, error);
      return {std::nullopt, native};
    }
    return {std::move(temporaryPath), 0};
  } catch (...) {
    return {std::nullopt, static_cast<std::uint32_t>(EIO)};
  }
}

std::uint32_t LinuxArtifactStore::Promote(
    std::filesystem::path const& temporaryPath,
    std::filesystem::path const& finalPath) const noexcept {
  try {
    std::error_code error;
    std::filesystem::remove(finalPath, error);
    error.clear();
    std::filesystem::rename(temporaryPath, finalPath, error);
    return static_cast<std::uint32_t>(error.value());
  } catch (...) {
    return static_cast<std::uint32_t>(EIO);
  }
}

void LinuxArtifactStore::Remove(
    std::filesystem::path const& path) const noexcept {
  std::error_code ignored;
  std::filesystem::remove(path, ignored);
}
}  // namespace upx_killer::elf_host::storage
