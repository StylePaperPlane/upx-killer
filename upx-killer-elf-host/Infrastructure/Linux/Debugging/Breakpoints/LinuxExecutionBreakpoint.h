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
  ~LinuxExecutionBreakpoint();
  LinuxExecutionBreakpoint(LinuxExecutionBreakpoint const&) = delete;
  LinuxExecutionBreakpoint& operator=(LinuxExecutionBreakpoint const&) =
      delete;
  LinuxExecutionBreakpoint(LinuxExecutionBreakpoint&& other) noexcept;
  LinuxExecutionBreakpoint& operator=(LinuxExecutionBreakpoint&& other) noexcept;

  [[nodiscard]] static std::optional<LinuxExecutionBreakpoint> Install(
      pid_t pid, std::uint64_t address) noexcept;
  [[nodiscard]] BreakpointRestoreResult RestoreIfHit(
      int signal, engine::elf::ElfClass imageClass) noexcept;

 private:
  enum class Kind : std::uint8_t { Software, Hardware };

  LinuxExecutionBreakpoint(pid_t pid, std::uint64_t address,
                           std::byte originalByte) noexcept
      : kind_(Kind::Software), pid_(pid), address_(address),
        originalByte_(originalByte) {}
  LinuxExecutionBreakpoint(pid_t pid, std::uint64_t address,
                           unsigned long originalAddressRegister,
                           unsigned long originalStatusRegister,
                           unsigned long originalControlRegister) noexcept
      : kind_(Kind::Hardware),
        pid_(pid),
        address_(address),
        originalAddressRegister_(originalAddressRegister),
        originalStatusRegister_(originalStatusRegister),
        originalControlRegister_(originalControlRegister) {}

  [[nodiscard]] bool Restore() noexcept;
  void MoveFrom(LinuxExecutionBreakpoint&& other) noexcept;

  Kind kind_{Kind::Software};
  pid_t pid_{-1};
  std::uint64_t address_{};
  std::byte originalByte_{};
  unsigned long originalAddressRegister_{};
  unsigned long originalStatusRegister_{};
  unsigned long originalControlRegister_{};
  bool armed_{true};
};

}  // namespace upx_killer::elf_host::debugging
