#include "Infrastructure/Linux/Debugging/ThreadContext/LinuxThreadContext.h"

#include <elf.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace {
using upx_killer::engine::elf::ElfClass;

// Linux exposes this 17-word i386 PRSTATUS layout to a 64-bit tracer when the
// tracee is in IA32 compatibility mode. Keep it private: callers only see the
// class-neutral ThreadControlContext value.
struct I386GeneralRegisters final {
  std::uint32_t ebx;
  std::uint32_t ecx;
  std::uint32_t edx;
  std::uint32_t esi;
  std::uint32_t edi;
  std::uint32_t ebp;
  std::uint32_t eax;
  std::uint32_t ds;
  std::uint32_t es;
  std::uint32_t fs;
  std::uint32_t gs;
  std::uint32_t originalEax;
  std::uint32_t eip;
  std::uint32_t cs;
  std::uint32_t eflags;
  std::uint32_t esp;
  std::uint32_t ss;
};

static_assert(sizeof(I386GeneralRegisters) == 17U * sizeof(std::uint32_t));

template <typename T>
bool ReadRegisterSet(pid_t threadId, T& registers) noexcept {
  iovec view{&registers, sizeof(registers)};
  if (ptrace(PTRACE_GETREGSET, threadId,
             reinterpret_cast<void*>(static_cast<std::uintptr_t>(NT_PRSTATUS)),
             &view) != 0)
    return false;
  if (view.iov_len != sizeof(registers)) {
    errno = EPROTO;
    return false;
  }
  return true;
}

template <typename T>
bool WriteRegisterSet(pid_t threadId, T const& registers) noexcept {
  iovec view{const_cast<T*>(&registers), sizeof(registers)};
  return ptrace(PTRACE_SETREGSET, threadId,
                reinterpret_cast<void*>(
                    static_cast<std::uintptr_t>(NT_PRSTATUS)),
                &view) == 0;
}
}  // namespace

namespace upx_killer::elf_host::debugging {
std::optional<ThreadControlContext> LinuxThreadContext::Read(
    pid_t threadId, ElfClass imageClass) noexcept {
  if (imageClass == ElfClass::Bits32) {
    I386GeneralRegisters registers{};
    if (!ReadRegisterSet(threadId, registers)) return std::nullopt;
    return ThreadControlContext{registers.eip, registers.esp};
  }

  user_regs_struct registers{};
  if (!ReadRegisterSet(threadId, registers)) return std::nullopt;
  return ThreadControlContext{registers.rip, registers.rsp};
}

bool LinuxThreadContext::SetInstructionPointer(
    pid_t threadId, ElfClass imageClass,
    std::uint64_t instructionPointer) noexcept {
  if (imageClass == ElfClass::Bits32) {
    if (instructionPointer > std::numeric_limits<std::uint32_t>::max()) {
      errno = EOVERFLOW;
      return false;
    }
    I386GeneralRegisters registers{};
    if (!ReadRegisterSet(threadId, registers)) return false;
    registers.eip = static_cast<std::uint32_t>(instructionPointer);
    return WriteRegisterSet(threadId, registers);
  }

  user_regs_struct registers{};
  if (!ReadRegisterSet(threadId, registers)) return false;
  registers.rip = instructionPointer;
  return WriteRegisterSet(threadId, registers);
}
}  // namespace upx_killer::elf_host::debugging
