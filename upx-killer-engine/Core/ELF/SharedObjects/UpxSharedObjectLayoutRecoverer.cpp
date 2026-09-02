#include "Core/ELF/SharedObjects/UpxSharedObjectLayoutRecoverer.h"

#include "Core/ELF/Format/Internal/ElfClassTraits.h"

#include <algorithm>
#include <limits>

namespace {
using namespace upx_killer::engine::elf;

constexpr std::uint32_t NullProgramHeader = 0;
constexpr std::uint32_t LoadProgramHeader = 1;
constexpr std::uint32_t DynamicProgramHeader = 2;
constexpr std::uint32_t RelroProgramHeader = 0x6474e552;
constexpr std::uint64_t NullTag = 0;
constexpr std::uint64_t StringTableTag = 5;
constexpr std::uint64_t StringTableSizeTag = 10;

std::uint64_t ReadUnsigned(std::span<std::byte const> bytes,
                           std::size_t offset,
                           std::size_t width) noexcept {
  if ((width != 4 && width != 8) || offset > bytes.size() ||
      width > bytes.size() - offset)
    return 0;
  std::uint64_t value{};
  for (std::size_t index = 0; index < width; ++index)
    value |= static_cast<std::uint64_t>(
                 std::to_integer<std::uint8_t>(bytes[offset + index]))
             << (index * 8);
  return value;
}

std::optional<std::uint64_t> MetadataEnd(
    std::span<std::byte const> bytes,
    ElfImageLayout const& layout) noexcept {
  auto const& traits = internal::GetElfClassTraits(layout.imageClass);
  auto const dynamic = std::find_if(
      layout.programHeaders.begin(), layout.programHeaders.end(),
      [](auto const& header) { return header.type == DynamicProgramHeader; });
  if (dynamic == layout.programHeaders.end() ||
      dynamic->fileSize < traits.dynamicEntrySize ||
      dynamic->fileSize % traits.dynamicEntrySize != 0 ||
      dynamic->fileOffset > bytes.size() ||
      dynamic->fileSize > bytes.size() - dynamic->fileOffset)
    return std::nullopt;
  std::uint64_t stringTable{};
  std::uint64_t stringTableSize{};
  bool terminated{};
  for (std::uint64_t cursor = 0; cursor < dynamic->fileSize;
       cursor += traits.dynamicEntrySize) {
    auto const offset = static_cast<std::size_t>(dynamic->fileOffset + cursor);
    auto const tag = ReadUnsigned(bytes, offset, traits.addressWidth);
    auto const value =
        ReadUnsigned(bytes, offset + traits.addressWidth, traits.addressWidth);
    if (tag == NullTag) {
      terminated = true;
      break;
    }
    if (tag == StringTableTag) stringTable = value;
    if (tag == StringTableSizeTag) stringTableSize = value;
  }
  if (!terminated || stringTable == 0 || stringTableSize == 0 ||
      stringTableSize > std::numeric_limits<std::uint64_t>::max() - stringTable)
    return std::nullopt;
  return stringTable + stringTableSize;
}
}  // namespace

namespace upx_killer::engine::elf::shared_objects {
SharedObjectLayoutRecoveryResult UpxSharedObjectLayoutRecoverer::Recover(
    std::span<std::byte const> packedBytes,
    ElfImageLayout const& packedLayout) noexcept {
  try {
    if (packedLayout.imageType != ElfImageType::SharedObject ||
        packedLayout.entryPoint == 0)
      return {{}, "elf.shared_object.layout_not_packed"};
    auto metadataEnd = MetadataEnd(packedBytes, packedLayout);
    if (!metadataEnd) return {{}, "elf.shared_object.metadata_invalid"};
    auto recovered = packedLayout;
    recovered.entryPoint = 0;
    recovered.sectionHeaderOffset = 0;
    recovered.sectionHeaderEntrySize = 0;
    recovered.sectionHeaderCount = 0;
    ElfProgramHeader* firstLoad{};
    bool restoredExecutableLoad{};
    for (auto& header : recovered.programHeaders) {
      if (header.type == NullProgramHeader && header.virtualAddress != 0 &&
          header.fileSize != 0 && header.memorySize >= header.fileSize &&
          (header.flags & 4U) != 0) {
        header.type = LoadProgramHeader;
        restoredExecutableLoad = restoredExecutableLoad ||
                                 (header.flags & 1U) != 0;
      }
      if (header.type == LoadProgramHeader) {
        header.fileOffset = header.virtualAddress;
        header.physicalAddress = header.virtualAddress;
        if (header.virtualAddress == 0) firstLoad = &header;
      } else if (header.type == DynamicProgramHeader ||
                 header.type == RelroProgramHeader) {
        header.fileOffset = header.virtualAddress;
        header.physicalAddress = header.virtualAddress;
      }
    }
    if (!firstLoad || !restoredExecutableLoad ||
        *metadataEnd < recovered.programHeaderOffset +
                           static_cast<std::uint64_t>(
                               recovered.programHeaderEntrySize) *
                               recovered.programHeaderCount)
      return {{}, "elf.shared_object.layout_evidence_insufficient"};
    auto const nextLoad = std::min_element(
        recovered.programHeaders.begin(), recovered.programHeaders.end(),
        [](auto const& left, auto const& right) {
          auto const leftAddress =
              left.type == LoadProgramHeader && left.virtualAddress != 0
                  ? left.virtualAddress
                  : std::numeric_limits<std::uint64_t>::max();
          auto const rightAddress =
              right.type == LoadProgramHeader && right.virtualAddress != 0
                  ? right.virtualAddress
                  : std::numeric_limits<std::uint64_t>::max();
          return leftAddress < rightAddress;
        });
    if (nextLoad == recovered.programHeaders.end() ||
        nextLoad->virtualAddress == 0 || *metadataEnd > nextLoad->virtualAddress)
      return {{}, "elf.shared_object.layout_evidence_insufficient"};
    firstLoad->fileSize = *metadataEnd;
    firstLoad->memorySize = *metadataEnd;
    firstLoad->flags = 4;
    return {std::move(recovered), {}};
  } catch (...) {
    return {{}, "elf.shared_object.layout_recovery_failed"};
  }
}
}  // namespace upx_killer::engine::elf::shared_objects
