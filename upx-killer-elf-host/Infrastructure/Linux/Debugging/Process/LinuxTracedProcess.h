#pragma once

#include <sys/types.h>

#include <cstdint>
#include <filesystem>
#include <memory>

namespace upx_killer::elf_host::debugging {

enum class LinuxTraceLaunchError {
  None,
  Fork,
  Exec,
  Ptrace,
};

class LinuxTracedProcess final {
 public:
  ~LinuxTracedProcess();
  LinuxTracedProcess(LinuxTracedProcess const&) = delete;
  LinuxTracedProcess& operator=(LinuxTracedProcess const&) = delete;

  [[nodiscard]] pid_t Id() const noexcept { return pid_; }

 private:
  friend class LinuxTraceLauncher;
  explicit LinuxTracedProcess(pid_t pid) noexcept : pid_(pid) {}
  pid_t pid_{};
};

struct LinuxTraceLaunchResult {
  std::unique_ptr<LinuxTracedProcess> process;
  LinuxTraceLaunchError error{LinuxTraceLaunchError::None};
  std::uint32_t nativeCode{};
};

class LinuxTraceLauncher final {
 public:
  [[nodiscard]] static LinuxTraceLaunchResult Launch(
      std::filesystem::path const& target,
      std::filesystem::path const& workingDirectory) noexcept;
};

}  // namespace upx_killer::elf_host::debugging
