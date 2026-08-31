#pragma once

#include <sys/types.h>

#include <cstdint>
#include <optional>

namespace upx_killer::elf_host::debugging {

class LinuxSoftwareBreakpoint final {
 public:
  [[nodiscard]] static std::optional<LinuxSoftwareBreakpoint> Install(
      pid_t pid, std::uint64_t address) noexcept;
  [[nodiscard]] bool RestoreIfHit(pid_t pid, int signal) const noexcept;

 private:
  LinuxSoftwareBreakpoint(std::uint64_t address,
                          std::uint64_t alignedAddress,
                          long originalWord) noexcept
      : address_(address),
        alignedAddress_(alignedAddress),
        originalWord_(originalWord) {}
  std::uint64_t address_{};
  std::uint64_t alignedAddress_{};
  long originalWord_{};
};

}  // namespace upx_killer::elf_host::debugging
