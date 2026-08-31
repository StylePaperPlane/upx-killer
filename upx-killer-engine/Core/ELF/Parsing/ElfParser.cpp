#include "Core/ELF/Parsing/ElfParser.h"

#include <algorithm>
#include <limits>

namespace {
using namespace upx_killer::engine::elf;

constexpr std::size_t Elf64HeaderSize = 64;
constexpr std::size_t Elf64ProgramHeaderSize = 56;
constexpr std::uint16_t ExecutableType = 2;
constexpr std::uint16_t DynamicType = 3;
constexpr std::uint16_t X64Machine = 62;
constexpr std::uint32_t LoadProgramHeader = 1;
constexpr std::uint32_t InterpreterProgramHeader = 3;
constexpr std::uint32_t ExecutableFlag = 1;
constexpr std::uint16_t MaximumProgramHeaders = 128;

template <typename T>
bool Read(std::span<std::byte const> bytes, std::size_t offset,
          T& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  value = 0;
  for (std::size_t index = 0; index < sizeof(T); ++index) {
    value |= static_cast<T>(std::to_integer<std::uint8_t>(bytes[offset + index]))
             << (index * 8);
  }
  return true;
}

bool AddOverflows(std::uint64_t left, std::uint64_t right) noexcept {
  return right > std::numeric_limits<std::uint64_t>::max() - left;
}

bool IsPowerOfTwo(std::uint64_t value) noexcept {
  return value == 0 || (value & (value - 1)) == 0;
}
}

namespace upx_killer::engine::elf {
ElfParseResult ElfParser::Parse(std::span<std::byte const> bytes,
                                ElfParseExtent extent) noexcept {
  if (bytes.size() < Elf64HeaderSize) return {{}, ElfParseError::Truncated};
  if (std::to_integer<std::uint8_t>(bytes[0]) != 0x7f ||
      std::to_integer<std::uint8_t>(bytes[1]) != 'E' ||
      std::to_integer<std::uint8_t>(bytes[2]) != 'L' ||
      std::to_integer<std::uint8_t>(bytes[3]) != 'F')
    return {{}, ElfParseError::InvalidMagic};
  if (std::to_integer<std::uint8_t>(bytes[4]) != 2)
    return {{}, ElfParseError::UnsupportedClass};
  if (std::to_integer<std::uint8_t>(bytes[5]) != 1)
    return {{}, ElfParseError::UnsupportedEndianness};

  std::uint16_t type{}, machine{}, headerSize{}, phEntrySize{}, phCount{},
      shEntrySize{}, shCount{};
  std::uint32_t version{}, flags{};
  std::uint64_t entry{}, phOffset{}, shOffset{};
  if (!Read(bytes, 16, type) || !Read(bytes, 18, machine) ||
      !Read(bytes, 20, version) || !Read(bytes, 24, entry) ||
      !Read(bytes, 32, phOffset) || !Read(bytes, 40, shOffset) ||
      !Read(bytes, 48, flags) ||
      !Read(bytes, 52, headerSize) || !Read(bytes, 54, phEntrySize) ||
      !Read(bytes, 56, phCount) || !Read(bytes, 58, shEntrySize) ||
      !Read(bytes, 60, shCount))
    return {{}, ElfParseError::Truncated};
  if (machine != X64Machine) return {{}, ElfParseError::UnsupportedMachine};
  if (type != ExecutableType && type != DynamicType)
    return {{}, ElfParseError::UnsupportedType};
  if (version != 1 || headerSize != Elf64HeaderSize ||
      phEntrySize != Elf64ProgramHeaderSize || phCount == 0 ||
      phCount > MaximumProgramHeaders)
    return {{}, ElfParseError::InvalidProgramHeaders};
  if (AddOverflows(phOffset,
                   static_cast<std::uint64_t>(phEntrySize) * phCount) ||
      phOffset + static_cast<std::uint64_t>(phEntrySize) * phCount > bytes.size())
    return {{}, ElfParseError::InvalidProgramHeaders};
  if (extent == ElfParseExtent::CompleteFile && shCount != 0 &&
      (shEntrySize != 64 ||
       AddOverflows(shOffset,
                    static_cast<std::uint64_t>(shEntrySize) * shCount) ||
       shOffset + static_cast<std::uint64_t>(shEntrySize) * shCount >
           bytes.size()))
    return {{}, ElfParseError::InvalidSectionHeaders};

  ElfImageLayout layout{};
  layout.entryPoint = entry;
  layout.programHeaderOffset = phOffset;
  layout.programHeaderEntrySize = phEntrySize;
  layout.programHeaderCount = phCount;
  layout.sectionHeaderOffset = shOffset;
  layout.sectionHeaderEntrySize = shEntrySize;
  layout.sectionHeaderCount = shCount;
  layout.flags = flags;
  layout.programHeaders.reserve(phCount);
  bool hasInterpreter{};
  bool entryIsExecutable{};
  bool hasLoad{};

  for (std::uint16_t index = 0; index < phCount; ++index) {
    auto const offset = static_cast<std::size_t>(
        phOffset + static_cast<std::uint64_t>(index) * phEntrySize);
    ElfProgramHeader header{};
    if (!Read(bytes, offset, header.type) ||
        !Read(bytes, offset + 4, header.flags) ||
        !Read(bytes, offset + 8, header.fileOffset) ||
        !Read(bytes, offset + 16, header.virtualAddress) ||
        !Read(bytes, offset + 24, header.physicalAddress) ||
        !Read(bytes, offset + 32, header.fileSize) ||
        !Read(bytes, offset + 40, header.memorySize) ||
        !Read(bytes, offset + 48, header.alignment))
      return {{}, ElfParseError::InvalidProgramHeaders};
    if (header.type == InterpreterProgramHeader) hasInterpreter = true;
    if (header.type == LoadProgramHeader) {
      hasLoad = true;
      if (header.fileSize > header.memorySize ||
          AddOverflows(header.virtualAddress, header.memorySize) ||
          AddOverflows(header.fileOffset, header.fileSize) ||
          !IsPowerOfTwo(header.alignment) ||
          (header.alignment > 1 &&
           header.virtualAddress % header.alignment !=
               header.fileOffset % header.alignment))
        return {{}, ElfParseError::InvalidLoadSegment};
      if ((header.flags & ExecutableFlag) != 0 && entry >= header.virtualAddress &&
          entry < header.virtualAddress + header.memorySize)
        entryIsExecutable = true;
    }
    layout.programHeaders.push_back(header);
  }
  if (!hasLoad) return {{}, ElfParseError::InvalidLoadSegment};
  if (entry == 0 || !entryIsExecutable)
    return {{}, ElfParseError::InvalidEntryPoint};

  if (type == ExecutableType) {
    layout.imageType = ElfImageType::Executable;
  } else if (hasInterpreter || entry != 0) {
    layout.imageType = ElfImageType::PositionIndependentExecutable;
  } else {
    layout.imageType = ElfImageType::SharedObject;
  }
  return {std::move(layout), ElfParseError::None};
}
}  // namespace upx_killer::engine::elf
