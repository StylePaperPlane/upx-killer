#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace upx_killer::elf_host::debugging {

struct LinuxMemoryMapping {
  std::uint64_t begin{};
  std::uint64_t end{};
  bool read{};
  bool write{};
  bool execute{};
  std::uint64_t offset{};
  std::string path;
};

class LinuxProcessMemory final {
 public:
  [[nodiscard]] static std::vector<LinuxMemoryMapping> ReadMappings(pid_t pid);
  [[nodiscard]] static bool Read(pid_t pid, std::uint64_t address,
                                 std::span<std::byte> output) noexcept;
};

}  // namespace upx_killer::elf_host::debugging
