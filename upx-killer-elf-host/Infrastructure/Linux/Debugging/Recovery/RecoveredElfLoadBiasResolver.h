#pragma once

#include "Core/ELF/Format/ElfImage.h"
#include "Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.h"

#include <cstdint>
#include <optional>
#include <span>

namespace upx_killer::elf_host::debugging {

class RecoveredElfLoadBiasResolver final {
 public:
  [[nodiscard]] static std::optional<std::uint64_t> Resolve(
      engine::elf::ElfImageLayout const& layout,
      std::uint64_t headerAddress,
      std::span<LinuxMemoryMapping const> mappings) noexcept;
};

}  // namespace upx_killer::elf_host::debugging
