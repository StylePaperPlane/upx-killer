#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <optional>

namespace upx_killer::elf_host::debugging {

enum class BreakpointRestoreResult : std::uint8_t {
  NotHit,
  Restored,
  Failed,
};

class LinuxExecutionBreakpoint final {
 public:
  [[nodiscard]] static std::optional<LinuxExecutionBreakpoint> Install(
      pid_t pid, std::uint64_t address) noexcept;
  [[nodiscard]] BreakpointRestoreResult RestoreIfHit(
      pid_t pid, int signal, engine::elf::ElfClass imageClass) const noexcept;

 private:
  enum class Kind : std::uint8_t { Software, Hardware };

  LinuxExecutionBreakpoint(std::uint64_t address,
                           std::byte originalByte) noexcept
      : kind_(Kind::Software), address_(address), originalByte_(originalByte) {}
  LinuxExecutionBreakpoint(std::uint64_t address,
                           unsigned long originalAddressRegister,
                           unsigned long originalControlRegister) noexcept
      : kind_(Kind::Hardware),
        address_(address),
        originalAddressRegister_(originalAddressRegister),
        originalControlRegister_(originalControlRegister) {}

  Kind kind_{Kind::Software};
  std::uint64_t address_{};
  std::byte originalByte_{};
  unsigned long originalAddressRegister_{};
  unsigned long originalControlRegister_{};
};

}  // namespace upx_killer::elf_host::debugging
