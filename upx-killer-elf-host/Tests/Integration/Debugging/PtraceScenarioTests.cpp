#include "Infrastructure/Linux/Debugging/Breakpoints/LinuxExecutionBreakpoint.h"
#include "Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.h"
#include "Infrastructure/Linux/Debugging/ThreadContext/LinuxThreadContext.h"
#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.h"
#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfLoadBiasResolver.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {
using upx_killer::elf_host::debugging::LinuxThreadContext;
using upx_killer::engine::elf::ElfClass;

constexpr auto DebugAddressOffset = offsetof(user, u_debugreg[0]);
constexpr auto DebugStatusOffset = offsetof(user, u_debugreg[6]);
constexpr auto DebugControlOffset = offsetof(user, u_debugreg[7]);

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

std::optional<unsigned long> ReadDebugRegister(pid_t pid,
                                               std::size_t offset) {
  errno = 0;
  auto const value = ptrace(PTRACE_PEEKUSER, pid,
                            reinterpret_cast<void*>(offset), nullptr);
  if (value == -1 && errno != 0) return std::nullopt;
  return static_cast<unsigned long>(value);
}

std::optional<std::uint64_t> FindSharedExecutableMapping(pid_t pid) {
  auto const mappings =
      upx_killer::elf_host::debugging::LinuxProcessMemory::ReadMappings(pid);
  auto const found = std::find_if(mappings.begin(), mappings.end(),
                                  [](auto const& mapping) {
    return mapping.execute &&
           mapping.path.find("memfd:upx-killer-hardware-breakpoint") !=
               std::string::npos;
  });
  if (found == mappings.end()) return std::nullopt;
  return found->begin;
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

void TestIllegalInstruction(std::filesystem::path const& executable) {
  auto const pid = LaunchTraced(executable, "illegal");
  Expect(pid > 0 && WaitStopped(pid, SIGTRAP),
         "illegal-instruction tracee initial stop");
  if (pid <= 0) return;
  if (!Continue(pid) || !WaitStopped(pid, SIGILL)) {
    Expect(false, "illegal instruction is surfaced as SIGILL");
    KillAndReap(pid);
    return;
  }
  Expect(Continue(pid, SIGILL), "forward illegal instruction");
  int status{};
  Expect(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
             WTERMSIG(status) == SIGILL,
         "illegal-instruction tracee preserves SIGILL termination");
}

void TestHardwareBreakpointCleanup(std::filesystem::path const& executable) {
  using upx_killer::elf_host::debugging::BreakpointRestoreResult;
  using upx_killer::elf_host::debugging::LinuxExecutionBreakpoint;

  auto launchReady = [&]() -> std::pair<pid_t, std::uint64_t> {
    auto const pid = LaunchTraced(executable, "hardware-breakpoint");
    if (pid <= 0 || !WaitStopped(pid, SIGTRAP) || !Continue(pid) ||
        !WaitStopped(pid, SIGSTOP)) {
      if (pid > 0) KillAndReap(pid);
      return {-1, 0};
    }
    auto const address = FindSharedExecutableMapping(pid);
    if (!address) {
      KillAndReap(pid);
      return {-1, 0};
    }
    return {pid, *address};
  };

  auto [hitPid, hitAddress] = launchReady();
  Expect(hitPid > 0, "hardware-breakpoint tracee reaches shared code mapping");
  if (hitPid > 0) {
    auto const originalAddress = ReadDebugRegister(hitPid, DebugAddressOffset);
    auto const originalStatus = ReadDebugRegister(hitPid, DebugStatusOffset);
    auto const originalControl = ReadDebugRegister(hitPid, DebugControlOffset);
    auto breakpoint = LinuxExecutionBreakpoint::Install(hitPid, hitAddress);
    Expect(originalAddress && originalStatus && originalControl && breakpoint,
           "hardware execution breakpoint installs on read-only shared code");
    if (breakpoint) {
      auto const armedAddress = ReadDebugRegister(hitPid, DebugAddressOffset);
      auto const armedControl = ReadDebugRegister(hitPid, DebugControlOffset);
      Expect(armedAddress && *armedAddress == hitAddress && armedControl &&
                 (*armedControl & 1u) != 0,
             "hardware execution breakpoint arms debug register zero");
      if (!Continue(hitPid) || !WaitStopped(hitPid, SIGTRAP)) {
        Expect(false, "hardware execution breakpoint is hit");
        KillAndReap(hitPid);
      } else {
        Expect(breakpoint->RestoreIfHit(SIGTRAP, ElfClass::Bits64) ==
                   BreakpointRestoreResult::Restored,
               "hardware execution breakpoint restores after a hit");
        Expect(ReadDebugRegister(hitPid, DebugAddressOffset) ==
                       originalAddress &&
                   ReadDebugRegister(hitPid, DebugStatusOffset) ==
                       originalStatus &&
                   ReadDebugRegister(hitPid, DebugControlOffset) ==
                       originalControl,
               "hardware breakpoint hit restores DR0, DR6, and DR7");
        Expect(Continue(hitPid), "continue after hardware breakpoint hit");
        int status{};
        Expect(waitpid(hitPid, &status, 0) == hitPid && WIFEXITED(status) &&
                   WEXITSTATUS(status) == 0,
               "tracee exits after hardware breakpoint restoration");
      }
    } else {
      KillAndReap(hitPid);
    }
  }

  auto [cleanupPid, cleanupAddress] = launchReady();
  Expect(cleanupPid > 0,
         "hardware-breakpoint cleanup tracee reaches shared code mapping");
  if (cleanupPid <= 0) return;
  auto const originalAddress = ReadDebugRegister(cleanupPid, DebugAddressOffset);
  auto const originalStatus = ReadDebugRegister(cleanupPid, DebugStatusOffset);
  auto const originalControl = ReadDebugRegister(cleanupPid, DebugControlOffset);
  {
    auto breakpoint =
        LinuxExecutionBreakpoint::Install(cleanupPid, cleanupAddress);
    Expect(breakpoint.has_value(),
           "hardware execution breakpoint installs for scope cleanup");
  }
  Expect(ReadDebugRegister(cleanupPid, DebugAddressOffset) == originalAddress &&
             ReadDebugRegister(cleanupPid, DebugStatusOffset) ==
                 originalStatus &&
             ReadDebugRegister(cleanupPid, DebugControlOffset) ==
                 originalControl,
         "unhit hardware breakpoint restores DR0, DR6, and DR7 on cleanup");
  Expect(Continue(cleanupPid), "continue after unhit breakpoint cleanup");
  int status{};
  Expect(waitpid(cleanupPid, &status, 0) == cleanupPid && WIFEXITED(status) &&
             WEXITSTATUS(status) == 0,
         "tracee runs without a stale hardware breakpoint");
  if (!WIFEXITED(status)) KillAndReap(cleanupPid);
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

void TestElf32DynamicLinkageReadiness() {
  using upx_killer::elf_host::debugging::RecoveredElfImageLocator;
  using namespace upx_killer::engine::elf;

  CapturedElfImage captured{};
  captured.layout.imageClass = ElfClass::Bits32;
  captured.layout.programHeaders = {
      {1, 6, 0, 0x1000, 0x1000, 0x200, 0x200, 0x1000},
      {2, 6, 0x100, 0x1100, 0x1100, 24, 24, 4},
  };
  CapturedElfSegment segment{};
  segment.programHeaderIndex = 0;
  segment.fileBytes.resize(0x200);
  auto write = [&](std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < sizeof(value); ++index)
      segment.fileBytes[offset + index] =
          static_cast<std::byte>((value >> (index * 8)) & 0xff);
  };
  write(0x100, 5);
  write(0x104, 0x1180);
  write(0x108, 6);
  write(0x10c, 0x1140);
  write(0x110, 0);
  write(0x114, 0);
  captured.segments.push_back(std::move(segment));

  Expect(RecoveredElfImageLocator::HasCompleteDynamicLinkage(captured),
         "ELF32 readiness decodes 8-byte dynamic entries");
  captured.layout.programHeaders[1].fileSize = 16;
  Expect(!RecoveredElfImageLocator::HasCompleteDynamicLinkage(captured),
         "ELF32 readiness rejects a dynamic table without a terminator");
}

void TestElf32PieLoadBiasResolution() {
  using namespace upx_killer::elf_host::debugging;
  using namespace upx_killer::engine::elf;
  constexpr std::uint64_t expectedBias = 0xf7000000;

  ElfImageLayout layout{};
  layout.imageClass = ElfClass::Bits32;
  layout.machine = ElfMachine::X86;
  layout.imageType = ElfImageType::PositionIndependentExecutable;
  layout.programHeaders = {
      {1, 4, 0, 0, 0, 0x200, 0x200, 0x1000},
      {1, 5, 0x1000, 0x1000, 0x1000, 0x100, 0x100, 0x1000},
      {1, 4, 0x2000, 0x2000, 0x2000, 0x2010, 0x2010, 0x1000},
      {1, 6, 0x4f98, 0x5f98, 0x5f98, 0x68, 0x68, 0x1000},
  };
  std::vector<LinuxMemoryMapping> mappings{
      {expectedBias, expectedBias + 0x1000, true, false, true, 0, {}},
      {expectedBias + 0x1000, expectedBias + 0x2000, true, false, true,
       0, {}},
      {expectedBias + 0x2000, expectedBias + 0x5000, true, false, false,
       0, {}},
      {expectedBias + 0x5000, expectedBias + 0x6000, true, true, false,
       0, {}},
  };
  auto const resolved = RecoveredElfLoadBiasResolver::Resolve(
      layout, expectedBias, mappings);
  Expect(resolved && *resolved == expectedBias,
         "ELF32 PIE load bias is anchored to the recovered ELF header");

  mappings[2].begin += 0x1000;
  Expect(!RecoveredElfLoadBiasResolver::Resolve(layout, expectedBias, mappings),
         "ELF32 PIE load bias rejects incomplete load mappings");

  layout.programHeaders = {
      {1, 5, 0, 0, 0, 0x100, 0x100, 0x1000},
      {1, 5, 0x1000, UINT64_MAX - 0x7ff, UINT64_MAX - 0x7ff,
       0x1000, 0x1000, 0x1000},
  };
  Expect(!RecoveredElfLoadBiasResolver::Resolve(
             layout, expectedBias, std::span{mappings}),
         "ELF32 PIE load bias rejects overflowing runtime ranges");
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
  TestIllegalInstruction(argv[1]);
  TestTimeoutCleanup(argv[1]);
  TestMultithreadEvent(argv[1]);
  TestHardwareBreakpointCleanup(argv[1]);
  TestElf32DynamicLinkageReadiness();
  TestElf32PieLoadBiasResolution();
  if (failures != 0) {
    std::cerr << failures << " ptrace integration test(s) failed\n";
    return 1;
  }
  std::cout << "All ptrace integration tests passed\n";
  return 0;
}
