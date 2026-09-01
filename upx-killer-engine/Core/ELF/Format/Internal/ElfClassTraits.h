#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <cstddef>
#include <cstdint>

namespace upx_killer::engine::elf::internal {

struct ElfClassTraits final {
  ElfClass imageClass;
  ElfMachine machine;
  std::uint8_t classIdentifier;
  std::uint16_t machineIdentifier;
  std::uint8_t addressWidth;
  std::size_t headerSize;
  std::size_t programHeaderSize;
  std::size_t sectionHeaderSize;
  std::size_t entryOffset;
  std::size_t programHeaderOffsetOffset;
  std::size_t sectionHeaderOffsetOffset;
  std::size_t flagsOffset;
  std::size_t headerSizeOffset;
  std::size_t programHeaderEntrySizeOffset;
  std::size_t programHeaderCountOffset;
  std::size_t sectionHeaderEntrySizeOffset;
  std::size_t sectionHeaderCountOffset;
  std::size_t programFlagsOffset;
  std::size_t programFileOffsetOffset;
  std::size_t programVirtualAddressOffset;
  std::size_t programPhysicalAddressOffset;
  std::size_t programFileSizeOffset;
  std::size_t programMemorySizeOffset;
  std::size_t programAlignmentOffset;
  std::size_t dynamicEntrySize;
  std::size_t symbolEntrySize;
  std::size_t relEntrySize;
  std::size_t relaEntrySize;
  std::size_t sectionFlagsOffset;
  std::size_t sectionAddressOffset;
  std::size_t sectionFileOffsetOffset;
  std::size_t sectionSizeOffset;
  std::size_t sectionLinkOffset;
  std::size_t sectionAlignmentOffset;
  std::size_t sectionEntrySizeOffset;
};

inline constexpr ElfClassTraits Elf32Traits{
    ElfClass::Bits32, ElfMachine::X86, 1, 3, 4, 52, 32, 40,
    24, 28, 32, 36, 40, 42, 44, 46, 48,
    24, 4, 8, 12, 16, 20, 28,
    8, 16, 8, 12, 8, 12, 16, 20, 24, 32, 36};

inline constexpr ElfClassTraits Elf64Traits{
    ElfClass::Bits64, ElfMachine::X64, 2, 62, 8, 64, 56, 64,
    24, 32, 40, 48, 52, 54, 56, 58, 60,
    4, 8, 16, 24, 32, 40, 48,
    16, 24, 16, 24, 8, 16, 24, 32, 40, 48, 56};

[[nodiscard]] inline constexpr ElfClassTraits const* FindElfClassTraits(
    std::uint8_t classIdentifier) noexcept {
  if (classIdentifier == Elf32Traits.classIdentifier) return &Elf32Traits;
  if (classIdentifier == Elf64Traits.classIdentifier) return &Elf64Traits;
  return nullptr;
}

[[nodiscard]] inline constexpr ElfClassTraits const& GetElfClassTraits(
    ElfClass imageClass) noexcept {
  return imageClass == ElfClass::Bits32 ? Elf32Traits : Elf64Traits;
}

}  // namespace upx_killer::engine::elf::internal
