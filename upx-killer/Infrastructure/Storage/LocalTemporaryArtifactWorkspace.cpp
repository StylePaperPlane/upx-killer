#include "pch.h"
#include "Infrastructure/Storage/LocalTemporaryArtifactWorkspace.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwctype>

namespace {
std::atomic_uint64_t allocationSequence{};

void CleanupStaleArtifacts(std::filesystem::path const& root) noexcept {
  try {
    if (!std::filesystem::is_directory(root)) return;
    auto const cutoff = std::filesystem::file_time_type::clock::now() -
                        std::chrono::hours{24 * 7};
    for (auto const& entry : std::filesystem::directory_iterator(root)) {
      std::error_code error;
      if (entry.is_directory(error) && !error &&
          entry.last_write_time(error) < cutoff && !error) {
        std::filesystem::remove_all(entry.path(), error);
      }
    }
  } catch (...) {
  }
}

std::wstring ArtifactExtension(std::filesystem::path const& targetPath) {
  auto extension = targetPath.extension().wstring();
  std::transform(extension.begin(), extension.end(), extension.begin(),
                 [](wchar_t value) {
                   return static_cast<wchar_t>(std::towlower(value));
                 });
  return extension == L".dll" ? L".dll" : L".exe";
}
}

namespace upx_killer::infrastructure {
application::TemporaryArtifactAllocationResult
LocalTemporaryArtifactWorkspace::Allocate(
    std::filesystem::path const& targetPath) const noexcept {
  try {
    if (!m_settingsStore || targetPath.empty()) {
      return {std::nullopt, "workspace.settings.unavailable"};
    }
    auto const settings = m_settingsStore->Load();
    if (settings.directory.empty()) {
      return {std::nullopt, "workspace.directory.invalid"};
    }
    if (settings.deleteAfterExport) CleanupStaleArtifacts(settings.directory);

    auto const sequence = allocationSequence.fetch_add(1, std::memory_order_relaxed);
    auto const session = std::to_wstring(GetCurrentProcessId()) + L"-" +
                         std::to_wstring(GetTickCount64()) + L"-" +
                         std::to_wstring(sequence);
    auto const outputPath = settings.directory / session /
        (targetPath.stem().wstring() + L".dumped" + ArtifactExtension(targetPath));
    return {application::TemporaryArtifactAllocation{
                outputPath, !settings.deleteAfterExport},
            {}};
  } catch (std::filesystem::filesystem_error const& error) {
    return {std::nullopt, "workspace.allocation.failed",
            static_cast<std::uint32_t>(error.code().value())};
  } catch (...) {
    return {std::nullopt, "workspace.allocation.failed"};
  }
}
}
