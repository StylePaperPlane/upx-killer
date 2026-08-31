#include "Infrastructure/Linux/Verification/LinuxElfImageValidator.h"

#include "Core/ELF/Parsing/ElfParser.h"
#include "Core/ELF/Validation/ElfImageValidator.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <fstream>
#include <thread>
#include <vector>

namespace upx_killer::elf_host::verification {
LinuxElfValidationResult LinuxElfImageValidator::Validate(
    std::filesystem::path const& imagePath,
    std::filesystem::path const& dependencyDirectory,
    std::uint32_t timeoutMilliseconds) const noexcept {
  try {
    std::error_code error;
    auto const size = std::filesystem::file_size(imagePath, error);
    if (error || size == 0)
      return {false, false, static_cast<std::uint32_t>(error.value())};
    std::ifstream stream(imagePath, std::ios::binary);
    if (!stream) return {false, false, static_cast<std::uint32_t>(errno)};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    stream.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    if (!stream)
      return {false, false, static_cast<std::uint32_t>(errno)};
    auto parsed = engine::elf::ElfParser::Parse(bytes);
    auto validation = engine::elf::ElfImageValidator::Validate(bytes);
    if (!parsed.layout || !validation.valid)
      return {false, false, static_cast<std::uint32_t>(ENOEXEC)};

    auto const pid = fork();
    if (pid < 0) return {true, false, static_cast<std::uint32_t>(errno)};
    if (pid == 0) {
      (void)setpgid(0, 0);
      (void)chdir(dependencyDirectory.c_str());
      if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(126);
      auto executable = imagePath.string();
      char* arguments[] = {executable.data(), nullptr};
      execv(executable.c_str(), arguments);
      _exit(127);
    }

    auto const deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMilliseconds);
    int status{};
    for (;;) {
      auto const waited = waitpid(pid, &status, WNOHANG);
      if (waited == pid) break;
      if (waited < 0 && errno != EINTR) {
        auto const native = static_cast<std::uint32_t>(errno);
        (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL);
        return {true, false, native};
      }
      if (std::chrono::steady_clock::now() >= deadline) {
        (void)kill(-pid, SIGKILL);
        (void)kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return {true, false, static_cast<std::uint32_t>(ETIMEDOUT)};
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto const accepted = WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP;
    (void)kill(-pid, SIGKILL);
    (void)kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    return {true, accepted,
            accepted ? 0u : static_cast<std::uint32_t>(ENOEXEC)};
  } catch (...) {
    return {false, false, static_cast<std::uint32_t>(EIO)};
  }
}
}  // namespace upx_killer::elf_host::verification
