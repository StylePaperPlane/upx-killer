#include "Core/PE/Parsing/PeParser.h"

#include "Core/PE/Format/PeFormatTraits.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>

namespace {
template <typename T>
bool Read(std::span<std::byte const> bytes, std::size_t offset, T& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return true;
}

bool IsPowerOfTwo(std::uint32_t value) noexcept {
  return value != 0 && (value & (value - 1)) == 0;
}

bool RangeFits(std::uint64_t offset, std::uint64_t size, std::uint64_t limit) noexcept {
  return offset <= limit && size <= limit - offset;
}

template <typename Traits>
upx_killer::engine::pe::PeParseResult ParseTyped(
    std::span<std::byte const> bytes, std::uint32_t ntOffset,
    IMAGE_FILE_HEADER const& fileHeader, std::size_t optionalOffset) noexcept {
  using namespace upx_killer::engine::pe;
  using OptionalHeader = typename Traits::OptionalHeader;

  if (fileHeader.Machine != Traits::Machine)
    return {std::nullopt, PeError::UnsupportedArchitecture};
  if (fileHeader.SizeOfOptionalHeader < sizeof(OptionalHeader))
    return {std::nullopt, PeError::Truncated};

  OptionalHeader optional{};
  if (!Read(bytes, optionalOffset, optional)) return {std::nullopt, PeError::Truncated};
  if (optional.Magic != Traits::OptionalHeaderMagic)
    return {std::nullopt, PeError::InvalidSignature};
  if (!IsPowerOfTwo(optional.FileAlignment) || !IsPowerOfTwo(optional.SectionAlignment) ||
      optional.FileAlignment > optional.SectionAlignment || optional.SizeOfImage == 0 ||
      optional.SizeOfImage > (1u << 30) || optional.SizeOfHeaders > optional.SizeOfImage ||
      optional.ImageBase == 0)
    return {std::nullopt, PeError::InvalidAlignment};

  auto const sectionOffset =
      static_cast<std::uint64_t>(optionalOffset) + fileHeader.SizeOfOptionalHeader;
  auto const tableSize =
      static_cast<std::uint64_t>(fileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
  if (!RangeFits(sectionOffset, tableSize, bytes.size()))
    return {std::nullopt, PeError::Truncated};

  PeImageLayout layout{};
  layout.format = Traits::Format;
  layout.imageKind = (fileHeader.Characteristics & IMAGE_FILE_DLL) != 0
                         ? PeImageKind::DynamicLibrary
                         : PeImageKind::Executable;
  layout.machine = fileHeader.Machine;
  layout.ntHeaderOffset = ntOffset;
  layout.preferredImageBase = optional.ImageBase;
  layout.entryPoint = {optional.AddressOfEntryPoint};
  layout.sizeOfImage = optional.SizeOfImage;
  layout.sizeOfHeaders = optional.SizeOfHeaders;
  layout.sectionAlignment = optional.SectionAlignment;
  layout.fileAlignment = optional.FileAlignment;
  layout.characteristics = fileHeader.Characteristics;
  layout.dllCharacteristics = optional.DllCharacteristics;
  auto const directoryCount =
      std::min<std::size_t>(optional.NumberOfRvaAndSizes, PeDirectoryCount);
  for (std::size_t index = 0; index < directoryCount; ++index) {
    layout.directories[index] = {{optional.DataDirectory[index].VirtualAddress},
                                 optional.DataDirectory[index].Size};
  }
  auto const& relocations = layout.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  layout.sourceLoadPolicy = {
      optional.ImageBase,
      (optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0,
      (optional.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0,
      relocations.address.value != 0 && relocations.size != 0};

  std::uint64_t previousEnd{};
  for (std::uint16_t index = 0; index < fileHeader.NumberOfSections; ++index) {
    IMAGE_SECTION_HEADER section{};
    if (!Read(bytes, static_cast<std::size_t>(sectionOffset + index * sizeof(section)), section))
      return {std::nullopt, PeError::Truncated};
    auto const virtualExtent = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
    if (!RangeFits(section.VirtualAddress, virtualExtent, optional.SizeOfImage) ||
        section.VirtualAddress < previousEnd)
      return {std::nullopt, PeError::InvalidSectionTable};
    if (section.SizeOfRawData != 0 &&
        !RangeFits(section.PointerToRawData, section.SizeOfRawData, bytes.size()))
      return {std::nullopt, PeError::Truncated};

    PeSection parsed{};
    std::memcpy(parsed.name.data(), section.Name, parsed.name.size());
    parsed.virtualAddress = {section.VirtualAddress};
    parsed.virtualSize = section.Misc.VirtualSize;
    parsed.rawOffset = {section.PointerToRawData};
    parsed.rawSize = section.SizeOfRawData;
    parsed.characteristics = section.Characteristics;
    layout.sections.push_back(parsed);
    previousEnd = static_cast<std::uint64_t>(section.VirtualAddress) + virtualExtent;
  }

  if (layout.entryPoint.value >= layout.sizeOfImage)
    return {std::nullopt, PeError::InvalidSectionTable};
  return {std::move(layout), PeError::None};
}
}

namespace upx_killer::engine::pe {
PeParseResult PeParser::Parse(std::span<std::byte const> bytes) noexcept {
  IMAGE_DOS_HEADER dos{};
  if (!Read(bytes, 0, dos)) return {std::nullopt, PeError::Truncated};
  if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < static_cast<LONG>(sizeof(dos)))
    return {std::nullopt, PeError::InvalidSignature};

  auto const ntOffset = static_cast<std::uint32_t>(dos.e_lfanew);
  DWORD signature{};
  IMAGE_FILE_HEADER fileHeader{};
  if (!Read(bytes, ntOffset, signature) ||
      !Read(bytes, ntOffset + sizeof(signature), fileHeader))
    return {std::nullopt, PeError::Truncated};
  if (signature != IMAGE_NT_SIGNATURE) return {std::nullopt, PeError::InvalidSignature};
  if ((fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0)
    return {std::nullopt, PeError::UnsupportedImageKind};
  if (fileHeader.NumberOfSections == 0 || fileHeader.NumberOfSections > 96)
    return {std::nullopt, PeError::InvalidSectionTable};

  auto const optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
  WORD magic{};
  if (!Read(bytes, optionalOffset, magic)) return {std::nullopt, PeError::Truncated};
  if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    return ParseTyped<format::Pe32Traits>(bytes, ntOffset, fileHeader, optionalOffset);
  if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    return ParseTyped<format::Pe64Traits>(bytes, ntOffset, fileHeader, optionalOffset);
  return {std::nullopt, PeError::InvalidSignature};
}
}
