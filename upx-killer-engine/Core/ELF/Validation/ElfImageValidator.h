#pragma once

#include "Core/ELF/Parsing/ElfParser.h"

#include <string>

namespace upx_killer::engine::elf {

struct ElfValidationResult {
  bool valid{};
  std::string detailCode;
};

class ElfImageValidator final {
 public:
  [[nodiscard]] static ElfValidationResult Validate(
      std::span<std::byte const> bytes) noexcept;
};

}  // namespace upx_killer::engine::elf
