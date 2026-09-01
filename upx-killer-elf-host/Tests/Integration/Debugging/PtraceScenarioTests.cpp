#include "Infrastructure/Linux/Debugging/ThreadContext/LinuxThreadContext.h"

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <string_view>
#include <thread>

namespace {
using upx_killer::elf_host::debugging::LinuxThreadContext;
using upx_killer::engine::elf::ElfClass;

int failures{};

void Expect(bool condition, std::string_view message) {
  if (condition) return;
  std::cerr << "FAIL: " << message << '\n';
  ++failures;
}

pid_t LaunchTraced(std::filesystem::path const& executable,
                   char const* scenario) {
  auto const pid = fork();
  if (pid != 0) return pid;
  if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) != 0) _exit(120);
  execl(executable.c_str(), executable.c_str(), scenario, nullptr);
  _exit(121);
}

bool WaitStopped(pid_t pid, int expectedSignal, int* statusOut = nullptr) {
  int status{};
  if (waitpid(pid, &status, 0) != pid) return false;
  if (statusOut) *statusOut = status;
  return WIFSTOPPED(status) && WSTOPSIG(status) == expectedSignal;
}

bool Continue(pid_t pid, int signal = 0) {
  return ptrace(PTRACE_CONT, pid, nullptr,
                reinterpret_cast<void*>(static_cast<intptr_t>(signal))) == 0;
}

void KillAndReap(pid_t pid) {
  kill(pid, SIGKILL);
  int status{};
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
}

void TestThreadContext(std::filesystem::path const& executable,
                       ElfClass imageClass, bool acceptsScenario) {
  auto const pid = LaunchTraced(executable, acceptsScenario ? "context" : "");
  Expect(pid > 0, "fork context tracee");
  if (pid <= 0) return;
  if (!WaitStopped(pid, SIGTRAP)) {
    Expect(false, "context tracee initial exec stop");
    KillAndReap(pid);
    return;
  }
  if (!Continue(pid) || !WaitStopped(pid, SIGSTOP)) {
    Expect(false, "context tracee controlled stop");
    KillAndReap(pid);
    return;
  }
  auto const before = LinuxThreadContext::Read(pid, imageClass);
  Expect(before.has_value(), "read class-neutral thread context");
  if (before) {
    Expect(before->instructionPointer != 0, "instruction pointer is present");
    Expect(before->stackPointer != 0, "stack pointer is present");
    Expect(LinuxThreadContext::SetInstructionPointer(
               pid, imageClass, before->instructionPointer),
           "write class-neutral instruction pointer");
    auto const after = LinuxThreadContext::Read(pid, imageClass);
    Expect(after && after->instructionPointer == before->instructionPointer,
           "instruction pointer round trip");
  }
  if (!Continue(pid)) {
    Expect(false, "continue context tracee");
    KillAndReap(pid);
    return;
  }
  int status{};
  Expect(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
             WEXITSTATUS(status) == 0,
         "context tracee exits normally");
}

void TestEarlyCrash(std::filesystem::path const& executable) {
  auto const pid = LaunchTraced(executable, "crash");
  Expect(pid > 0 && WaitStopped(pid, SIGTRAP), "crash tracee initial stop");
  if (pid <= 0) return;
  if (!Continue(pid) || !WaitStopped(pid, SIGSEGV)) {
    Expect(false, "early crash is surfaced as SIGSEGV");
    KillAndReap(pid);
    return;
  }
  Expect(Continue(pid, SIGSEGV), "forward crash signal");
  int status{};
  Expect(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
             WTERMSIG(status) == SIGSEGV,
         "crash tracee terminates with SIGSEGV");
}

void TestExceptionalSignal(std::filesystem::path const& executable) {
  auto const pid = LaunchTraced(executable, "signal");
  Expect(pid > 0 && WaitStopped(pid, SIGTRAP), "signal tracee initial stop");
  if (pid <= 0) return;
  if (!Continue(pid) || !WaitStopped(pid, SIGUSR1)) {
    Expect(false, "exceptional signal is surfaced");
    KillAndReap(pid);
    return;
  }
  Expect(Continue(pid, SIGUSR1), "forward exceptional signal");
  int status{};
  Expect(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
             WTERMSIG(status) == SIGUSR1,
         "signal tracee preserves termination signal");
}

void TestTimeoutCleanup(std::filesystem::path const& executable) {
  auto const pid = LaunchTraced(executable, "timeout");
  Expect(pid > 0 && WaitStopped(pid, SIGTRAP), "timeout tracee initial stop");
  if (pid <= 0) return;
  Expect(Continue(pid), "continue timeout tracee");
  auto const deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(40);
  int status{};
  bool exited{};
  while (std::chrono::steady_clock::now() < deadline) {
    auto const waited = waitpid(pid, &status, WNOHANG);
    if (waited == pid) {
      exited = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  Expect(!exited, "timeout tracee remains active until deadline");
  if (!exited) KillAndReap(pid);
  errno = 0;
  Expect(kill(pid, 0) == -1 && errno == ESRCH,
         "timeout cleanup leaves no tracee");
}

void TestMultithreadEvent(std::filesystem::path const& executable) {
  auto const pid = LaunchTraced(executable, "multithread");
  Expect(pid > 0 && WaitStopped(pid, SIGTRAP),
         "multithread tracee initial stop");
  if (pid <= 0) return;
  if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
             reinterpret_cast<void*>(PTRACE_O_TRACECLONE)) != 0 ||
      !Continue(pid)) {
    Expect(false, "enable clone event tracing");
    KillAndReap(pid);
    return;
  }

  bool sawClone{};
  bool mainExited{};
  while (!mainExited) {
    int status{};
    auto const waited = waitpid(-1, &status, __WALL);
    if (waited < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (waited == pid && WIFEXITED(status)) {
      mainExited = WEXITSTATUS(status) == 0;
      break;
    }
    if (WIFSTOPPED(status)) {
      auto const event = static_cast<unsigned>(status) >> 16;
      if (event == PTRACE_EVENT_CLONE) sawClone = true;
      if (!Continue(waited, WSTOPSIG(status) == SIGTRAP ? 0
                                                        : WSTOPSIG(status))) {
        break;
      }
    }
  }
  Expect(sawClone, "ptrace reports a clone event");
  Expect(mainExited, "multithread tracee exits normally");
  if (!mainExited) KillAndReap(pid);
}
}  // namespace

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: ptrace-tests <tracee64> <tracee32>\n";
    return 2;
  }
  TestThreadContext(argv[1], ElfClass::Bits64, true);
  TestThreadContext(argv[2], ElfClass::Bits32, false);
  TestEarlyCrash(argv[1]);
  TestExceptionalSignal(argv[1]);
  TestTimeoutCleanup(argv[1]);
  TestMultithreadEvent(argv[1]);
  if (failures != 0) {
    std::cerr << failures << " ptrace integration test(s) failed\n";
    return 1;
  }
  std::cout << "All ptrace integration tests passed\n";
  return 0;
}
