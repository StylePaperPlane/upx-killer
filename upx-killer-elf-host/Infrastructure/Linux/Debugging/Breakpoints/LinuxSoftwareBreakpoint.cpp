#include "Infrastructure/Linux/Debugging/Breakpoints/LinuxSoftwareBreakpoint.h"

#include <sys/ptrace.h>
#include <sys/user.h>

#include <cerrno>
#include <csignal>

namespace upx_killer::elf_host::debugging {
std::optional<LinuxSoftwareBreakpoint> LinuxSoftwareBreakpoint::Install(
    pid_t pid, std::uint64_t address) noexcept {
  auto const aligned = address & ~(static_cast<std::uint64_t>(sizeof(long)) - 1);
  auto const byteOffset = static_cast<unsigned>(address - aligned);
  errno = 0;
  auto const original = ptrace(PTRACE_PEEKDATA, pid,
                               reinterpret_cast<void*>(aligned), nullptr);
  if (original == -1 && errno != 0) return std::nullopt;
  auto modified = static_cast<unsigned long>(original);
  modified &= ~(0xfful << (byteOffset * 8));
  modified |= 0xccul << (byteOffset * 8);
  if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(aligned),
             reinterpret_cast<void*>(static_cast<std::uintptr_t>(modified))) != 0)
    return std::nullopt;
  return LinuxSoftwareBreakpoint{address, aligned, original};
}

bool LinuxSoftwareBreakpoint::RestoreIfHit(pid_t pid, int signal) const noexcept {
  user_regs_struct registers{};
  if (signal != SIGTRAP ||
      ptrace(PTRACE_GETREGS, pid, nullptr, &registers) != 0 ||
      registers.rip != address_ + 1)
    return false;
  if (ptrace(PTRACE_POKEDATA, pid,
             reinterpret_cast<void*>(alignedAddress_),
             reinterpret_cast<void*>(originalWord_)) != 0)
    return false;
  registers.rip = address_;
  return ptrace(PTRACE_SETREGS, pid, nullptr, &registers) == 0;
}
}  // namespace upx_killer::elf_host::debugging
