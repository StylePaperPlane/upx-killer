#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <span>

namespace upx_killer::engine::elf::reconstruction::internal {

class ElfHeaderWriter final {
 public:
  [[nodiscard]] static bool Write(
      std::span<std::byte> bytes,
      ElfImageLayout const& layout) noexcept;
};

}  // namespace upx_killer::engine::elf::reconstruction::internal
