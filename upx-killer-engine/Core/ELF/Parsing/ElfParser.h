#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <optional>
#include <span>

namespace upx_killer::engine::elf {

enum class ElfParseError : std::uint8_t {
  None,
  Truncated,
  InvalidMagic,
  UnsupportedClass,
  UnsupportedEndianness,
  UnsupportedMachine,
  UnsupportedType,
  InvalidProgramHeaders,
  InvalidSectionHeaders,
  InvalidLoadSegment,
  InvalidEntryPoint,
};

struct ElfParseResult {
  std::optional<ElfImageLayout> layout;
  ElfParseError error{ElfParseError::None};
};

enum class ElfParseExtent : std::uint8_t {
  CompleteFile,
  LoadedHeaders,
};

class ElfParser final {
 public:
  [[nodiscard]] static ElfParseResult Parse(
      std::span<std::byte const> bytes,
      ElfParseExtent extent = ElfParseExtent::CompleteFile) noexcept;
};

}  // namespace upx_killer::engine::elf
