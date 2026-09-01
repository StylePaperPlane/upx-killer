#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <sys/types.h>

#include <cstdint>
#include <optional>

namespace upx_killer::elf_host::debugging {

struct ThreadControlContext final {
  std::uint64_t instructionPointer{};
  std::uint64_t stackPointer{};
};

// Reads and updates only the control registers needed by the debugger. Native
// ptrace register layouts remain private to the Linux adapter.
class LinuxThreadContext final {
 public:
  [[nodiscard]] static std::optional<ThreadControlContext> Read(
      pid_t threadId, engine::elf::ElfClass imageClass) noexcept;

  [[nodiscard]] static bool SetInstructionPointer(
      pid_t threadId, engine::elf::ElfClass imageClass,
      std::uint64_t instructionPointer) noexcept;
};

}  // namespace upx_killer::elf_host::debugging
