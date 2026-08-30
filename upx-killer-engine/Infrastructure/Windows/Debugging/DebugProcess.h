#pragma once

#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace upx_killer::engine::debugging {
class DebugProcess final {
 public:
  DebugProcess() = default;
  ~DebugProcess();
  DebugProcess(DebugProcess const&) = delete;
  DebugProcess& operator=(DebugProcess const&) = delete;
  DebugProcess(DebugProcess&& other) noexcept;
  DebugProcess& operator=(DebugProcess&& other) noexcept;

  [[nodiscard]] static std::optional<DebugProcess> Launch(
      std::filesystem::path const& applicationPath, std::wstring commandLine,
      std::filesystem::path const& workingDirectory,
      std::uint32_t& nativeError) noexcept;

  [[nodiscard]] HANDLE ProcessHandle() const noexcept { return process_; }

  [[nodiscard]] DWORD ProcessId() const noexcept { return processId_; }

  void Terminate(std::uint32_t exitCode) noexcept;

 private:
  void Reset() noexcept;

  HANDLE process_{};
  HANDLE primaryThread_{};
  HANDLE job_{};
  DWORD processId_{};
};
}
