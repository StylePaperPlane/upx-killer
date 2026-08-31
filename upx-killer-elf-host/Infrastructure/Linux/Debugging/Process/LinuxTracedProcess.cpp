#include "Infrastructure/Linux/Debugging/Process/LinuxTracedProcess.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <fcntl.h>

#include <cerrno>
#include <csignal>

namespace upx_killer::elf_host::debugging {
LinuxTracedProcess::~LinuxTracedProcess() {
  if (pid_ <= 0) return;
  (void)kill(-pid_, SIGKILL);
  (void)kill(pid_, SIGKILL);
  int status{};
  while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
  }
}

LinuxTraceLaunchResult LinuxTraceLauncher::Launch(
    std::filesystem::path const& target,
    std::filesystem::path const& workingDirectory) noexcept {
  auto const pid = fork();
  if (pid < 0)
    return {nullptr, LinuxTraceLaunchError::Fork,
            static_cast<std::uint32_t>(errno)};
  if (pid == 0) {
    (void)setpgid(0, 0);
    (void)chdir(workingDirectory.c_str());
    auto const nullHandle = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (nullHandle >= 0) {
      (void)dup2(nullHandle, STDIN_FILENO);
      (void)dup2(nullHandle, STDOUT_FILENO);
      (void)dup2(nullHandle, STDERR_FILENO);
      if (nullHandle > STDERR_FILENO) (void)close(nullHandle);
    }
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(126);
    auto executable = target.string();
    char* arguments[] = {executable.data(), nullptr};
    execv(executable.c_str(), arguments);
    _exit(127);
  }

  auto process = std::unique_ptr<LinuxTracedProcess>{
      new LinuxTracedProcess{pid}};
  int status{};
  if (waitpid(pid, &status, 0) != pid || !WIFSTOPPED(status))
    return {nullptr, LinuxTraceLaunchError::Exec,
            static_cast<std::uint32_t>(errno)};
  auto const options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD;
  if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
             reinterpret_cast<void*>(options)) != 0 ||
      ptrace(PTRACE_SYSCALL, pid, nullptr, nullptr) != 0)
    return {nullptr, LinuxTraceLaunchError::Ptrace,
            static_cast<std::uint32_t>(errno)};
  return {std::move(process), LinuxTraceLaunchError::None, 0};
}
}  // namespace upx_killer::elf_host::debugging
