#include "Infrastructure/Linux/Loading/IsolatedElfLoadVerifier.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <thread>

namespace upx_killer::elf_host::loading {
IsolatedElfLoadResult IsolatedElfLoadVerifier::Verify(
    std::filesystem::path const& imagePath,
    engine::elf::ElfImageLayout const& layout,
    std::filesystem::path const& dependencyDirectory,
    std::uint32_t timeoutMilliseconds) const noexcept {
  try {
    auto executable = imagePath;
    auto isSharedObject = layout.imageType == engine::elf::ElfImageType::SharedObject;
    if (isSharedObject) {
      auto loader = loaders_.Resolve(layout.imageClass);
      if (!loader) return {false, static_cast<std::uint32_t>(ENOENT)};
      executable = std::move(*loader);
    }
    auto const pid = fork();
    if (pid < 0) return {false, static_cast<std::uint32_t>(errno)};
    if (pid == 0) {
      (void)setpgid(0, 0);
      (void)chdir(dependencyDirectory.c_str());
      if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(126);
      auto executableText = executable.string();
      auto imageText = imagePath.string();
      if (isSharedObject) {
        char* arguments[] = {executableText.data(), imageText.data(), nullptr};
        execv(executableText.c_str(), arguments);
      } else {
        char* arguments[] = {executableText.data(), nullptr};
        execv(executableText.c_str(), arguments);
      }
      _exit(127);
    }

    auto const deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMilliseconds);
    bool continuedAfterExec{};
    int status{};
    for (;;) {
      auto const waited = waitpid(pid, &status, WNOHANG);
      if (waited == pid) {
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP &&
            !continuedAfterExec) {
          if (!isSharedObject) {
            (void)kill(-pid, SIGKILL);
            (void)kill(pid, SIGKILL);
            while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
            return {true, 0};
          }
          if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) != 0) break;
          continuedAfterExec = true;
          continue;
        }
        if (isSharedObject && continuedAfterExec && WIFSTOPPED(status) &&
            WSTOPSIG(status) == SIGSTOP) {
          (void)kill(-pid, SIGKILL);
          (void)kill(pid, SIGKILL);
          while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
          return {true, 0};
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
      } else if (waited < 0 && errno != EINTR) {
        break;
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return {false, static_cast<std::uint32_t>(ETIMEDOUT)};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto const native = WIFEXITED(status)
                            ? static_cast<std::uint32_t>(WEXITSTATUS(status))
                            : static_cast<std::uint32_t>(ENOEXEC);
    (void)kill(-pid, SIGKILL);
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return {false, native};
  } catch (...) {
    return {false, static_cast<std::uint32_t>(EIO)};
  }
}
}  // namespace upx_killer::elf_host::loading
