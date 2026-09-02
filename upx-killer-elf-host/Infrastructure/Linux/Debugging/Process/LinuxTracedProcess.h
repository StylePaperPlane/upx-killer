#pragma once

#include <sys/types.h>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

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

enum class LinuxTraceStartMode : std::uint8_t {
  Continue,
  SystemCalls,
};

struct LinuxTraceLaunchRequest {
  std::filesystem::path executable;
  std::filesystem::path workingDirectory;
  std::vector<std::string> arguments;
  LinuxTraceStartMode startMode{LinuxTraceStartMode::SystemCalls};
};

class LinuxTraceLauncher final {
 public:
  [[nodiscard]] static LinuxTraceLaunchResult Launch(
      LinuxTraceLaunchRequest const& request) noexcept;
};

}  // namespace upx_killer::elf_host::debugging
