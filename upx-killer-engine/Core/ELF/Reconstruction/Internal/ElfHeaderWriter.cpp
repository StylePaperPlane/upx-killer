#include "Core/ELF/Reconstruction/Internal/ElfHeaderWriter.h"

#include "Core/ELF/Format/Internal/ElfClassTraits.h"

#include <limits>

namespace {
using namespace upx_killer::engine::elf;

template <typename T>
bool WriteValue(std::span<std::byte> bytes, std::size_t offset,
                T value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  for (std::size_t index = 0; index < sizeof(T); ++index)
    bytes[offset + index] =
        static_cast<std::byte>((value >> (index * 8)) & 0xff);
  return true;
}

bool WriteAddress(std::span<std::byte> bytes, std::size_t offset,
                  std::size_t width, std::uint64_t value) noexcept {
  if (width == 4) {
    if (value > std::numeric_limits<std::uint32_t>::max()) return false;
    return WriteValue(bytes, offset, static_cast<std::uint32_t>(value));
  }
  return width == 8 && WriteValue(bytes, offset, value);
}
}  // namespace

namespace upx_killer::engine::elf::reconstruction::internal {
bool ElfHeaderWriter::Write(std::span<std::byte> bytes,
                            ElfImageLayout const& layout) noexcept {
  auto const& traits = elf::internal::GetElfClassTraits(layout.imageClass);
  if (layout.programHeaders.size() != layout.programHeaderCount ||
      layout.programHeaderEntrySize != traits.programHeaderSize ||
      layout.programHeaderOffset > bytes.size() ||
      static_cast<std::uint64_t>(layout.programHeaderEntrySize) *
              layout.programHeaderCount >
          bytes.size() - layout.programHeaderOffset)
    return false;
  auto const type = layout.imageType == ElfImageType::Executable ? 2U : 3U;
  if (!WriteValue<std::uint16_t>(bytes, 16,
                                 static_cast<std::uint16_t>(type)) ||
      !WriteValue<std::uint16_t>(bytes, 18, traits.machineIdentifier) ||
      !WriteValue<std::uint32_t>(bytes, 20, 1) ||
      !WriteAddress(bytes, traits.entryOffset, traits.addressWidth,
                    layout.entryPoint) ||
      !WriteAddress(bytes, traits.programHeaderOffsetOffset,
                    traits.addressWidth, layout.programHeaderOffset) ||
      !WriteValue(bytes, traits.flagsOffset, layout.flags) ||
      !WriteValue<std::uint16_t>(bytes, traits.headerSizeOffset,
                                 static_cast<std::uint16_t>(traits.headerSize)) ||
      !WriteValue<std::uint16_t>(
          bytes, traits.programHeaderEntrySizeOffset,
          static_cast<std::uint16_t>(traits.programHeaderSize)) ||
      !WriteValue<std::uint16_t>(bytes, traits.programHeaderCountOffset,
                                 layout.programHeaderCount))
    return false;
  for (std::size_t index = 0; index < layout.programHeaders.size(); ++index) {
    auto const& header = layout.programHeaders[index];
    auto const offset = static_cast<std::size_t>(
        layout.programHeaderOffset + index * traits.programHeaderSize);
    if (!WriteValue(bytes, offset, header.type) ||
        !WriteValue(bytes, offset + traits.programFlagsOffset, header.flags) ||
        !WriteAddress(bytes, offset + traits.programFileOffsetOffset,
                      traits.addressWidth, header.fileOffset) ||
        !WriteAddress(bytes, offset + traits.programVirtualAddressOffset,
                      traits.addressWidth, header.virtualAddress) ||
        !WriteAddress(bytes, offset + traits.programPhysicalAddressOffset,
                      traits.addressWidth, header.physicalAddress) ||
        !WriteAddress(bytes, offset + traits.programFileSizeOffset,
                      traits.addressWidth, header.fileSize) ||
        !WriteAddress(bytes, offset + traits.programMemorySizeOffset,
                      traits.addressWidth, header.memorySize) ||
        !WriteAddress(bytes, offset + traits.programAlignmentOffset,
                      traits.addressWidth, header.alignment))
      return false;
  }
  return true;
}
}  // namespace upx_killer::engine::elf::reconstruction::internal
