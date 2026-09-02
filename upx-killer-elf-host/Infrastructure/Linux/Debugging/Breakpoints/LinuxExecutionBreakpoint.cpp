#include "Infrastructure/Linux/Debugging/Breakpoints/LinuxExecutionBreakpoint.h"

#include "Infrastructure/Linux/Debugging/ThreadContext/LinuxThreadContext.h"

#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace {
constexpr auto DebugAddressOffset = offsetof(user, u_debugreg[0]);
constexpr auto DebugStatusOffset = offsetof(user, u_debugreg[6]);
constexpr auto DebugControlOffset = offsetof(user, u_debugreg[7]);
constexpr unsigned long LocalBreakpointZero = 1;
constexpr unsigned long BreakpointZeroControlMask = 0xful << 16;

bool AccessTraceeByte(pid_t pid, std::uint64_t address, std::byte& value,
                      bool write) noexcept {
  auto const path = "/proc/" + std::to_string(pid) + "/mem";
  auto const descriptor = open(path.c_str(), O_RDWR | O_CLOEXEC);
  if (descriptor < 0) return false;
  auto const offset = static_cast<off_t>(address);
  auto const transferred = write ? pwrite(descriptor, &value, 1, offset)
                                 : pread(descriptor, &value, 1, offset);
  auto const savedError = errno;
  close(descriptor);
  errno = savedError;
  return transferred == 1;
}

std::optional<unsigned long> ReadDebugRegister(pid_t pid,
                                               std::size_t offset) noexcept {
  errno = 0;
  auto const value = ptrace(PTRACE_PEEKUSER, pid,
                            reinterpret_cast<void*>(offset), nullptr);
  if (value == -1 && errno != 0) return std::nullopt;
  return static_cast<unsigned long>(value);
}

bool WriteDebugRegister(pid_t pid, std::size_t offset,
                        unsigned long value) noexcept {
  return ptrace(PTRACE_POKEUSER, pid, reinterpret_cast<void*>(offset),
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(value))) ==
         0;
}
}  // namespace

namespace upx_killer::elf_host::debugging {
LinuxExecutionBreakpoint::~LinuxExecutionBreakpoint() { (void)Restore(); }

LinuxExecutionBreakpoint::LinuxExecutionBreakpoint(
    LinuxExecutionBreakpoint&& other) noexcept {
  MoveFrom(std::move(other));
}

LinuxExecutionBreakpoint& LinuxExecutionBreakpoint::operator=(
    LinuxExecutionBreakpoint&& other) noexcept {
  if (this == &other) return *this;
  (void)Restore();
  MoveFrom(std::move(other));
  return *this;
}

void LinuxExecutionBreakpoint::MoveFrom(
    LinuxExecutionBreakpoint&& other) noexcept {
  kind_ = other.kind_;
  pid_ = other.pid_;
  address_ = other.address_;
  originalByte_ = other.originalByte_;
  originalAddressRegister_ = other.originalAddressRegister_;
  originalStatusRegister_ = other.originalStatusRegister_;
  originalControlRegister_ = other.originalControlRegister_;
  armed_ = other.armed_;
  other.armed_ = false;
  other.pid_ = -1;
}

std::optional<LinuxExecutionBreakpoint> LinuxExecutionBreakpoint::Install(
    pid_t pid, std::uint64_t address) noexcept {
  std::byte original{};
  if (AccessTraceeByte(pid, address, original, false)) {
    auto breakpoint = std::byte{0xcc};
    if (AccessTraceeByte(pid, address, breakpoint, true))
      return LinuxExecutionBreakpoint{pid, address, original};
  }

  auto const originalAddress = ReadDebugRegister(pid, DebugAddressOffset);
  auto const originalStatus = ReadDebugRegister(pid, DebugStatusOffset);
  auto const originalControl = ReadDebugRegister(pid, DebugControlOffset);
  if (!originalAddress || !originalStatus || !originalControl ||
      !WriteDebugRegister(pid, DebugAddressOffset,
                          static_cast<unsigned long>(address)))
    return std::nullopt;
  auto const control =
      (*originalControl & ~(LocalBreakpointZero | BreakpointZeroControlMask)) |
      LocalBreakpointZero;
  if (!WriteDebugRegister(pid, DebugControlOffset, control)) {
    (void)WriteDebugRegister(pid, DebugAddressOffset, *originalAddress);
    return std::nullopt;
  }
  return LinuxExecutionBreakpoint{pid, address, *originalAddress,
                                  *originalStatus, *originalControl};
}

BreakpointRestoreResult LinuxExecutionBreakpoint::RestoreIfHit(
    int signal, engine::elf::ElfClass imageClass) noexcept {
  if (!armed_) return BreakpointRestoreResult::NotHit;
  if (signal != SIGTRAP) return BreakpointRestoreResult::NotHit;
  auto const context = LinuxThreadContext::Read(pid_, imageClass);
  if (!context) return BreakpointRestoreResult::Failed;

  if (kind_ == Kind::Hardware) {
    if (context->instructionPointer != address_)
      return BreakpointRestoreResult::NotHit;
    if (!Restore()) return BreakpointRestoreResult::Failed;
    return BreakpointRestoreResult::Restored;
  }

  if (context->instructionPointer != address_ + 1)
    return BreakpointRestoreResult::NotHit;
  auto original = originalByte_;
  if (!AccessTraceeByte(pid_, address_, original, true))
    return BreakpointRestoreResult::Failed;
  if (!LinuxThreadContext::SetInstructionPointer(pid_, imageClass, address_))
    return BreakpointRestoreResult::Failed;
  armed_ = false;
  return BreakpointRestoreResult::Restored;
}

bool LinuxExecutionBreakpoint::Restore() noexcept {
  if (!armed_) return true;
  bool restored{};
  if (kind_ == Kind::Software) {
    auto original = originalByte_;
    restored = AccessTraceeByte(pid_, address_, original, true);
  } else {
    auto const controlRestored = WriteDebugRegister(
        pid_, DebugControlOffset, originalControlRegister_);
    auto const addressRestored = WriteDebugRegister(
        pid_, DebugAddressOffset, originalAddressRegister_);
    auto const statusRestored = WriteDebugRegister(
        pid_, DebugStatusOffset, originalStatusRegister_);
    restored = controlRestored && addressRestored && statusRestored;
  }
  if (restored) armed_ = false;
  return restored;
}
}  // namespace upx_killer::elf_host::debugging
