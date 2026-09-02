#include "Core/ELF/Parsing/Internal/ElfImageTypeClassifier.h"

#include "Core/ELF/Format/Internal/ElfClassTraits.h"

namespace {
using namespace upx_killer::engine::elf;

constexpr std::uint32_t DynamicProgramHeader = 2;
constexpr std::uint64_t NullTag = 0;
constexpr std::uint64_t SonameTag = 14;

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

bool HasSoname(std::span<std::byte const> bytes,
               ElfImageLayout const& layout,
               ElfParseExtent extent) noexcept {
  if (extent != ElfParseExtent::CompleteFile) return false;
  auto const& traits = internal::GetElfClassTraits(layout.imageClass);
  for (auto const& header : layout.programHeaders) {
    if (header.type != DynamicProgramHeader ||
        header.fileSize < traits.dynamicEntrySize ||
        header.fileSize % traits.dynamicEntrySize != 0 ||
        header.fileOffset > bytes.size() ||
        header.fileSize > bytes.size() - header.fileOffset)
      continue;
    for (std::uint64_t cursor = 0; cursor < header.fileSize;
         cursor += traits.dynamicEntrySize) {
      auto const tag = ReadUnsigned(
          bytes, static_cast<std::size_t>(header.fileOffset + cursor),
          traits.addressWidth);
      if (tag == NullTag) break;
      if (tag == SonameTag) return true;
    }
  }
  return false;
}
}  // namespace

namespace upx_killer::engine::elf::parsing::internal {
std::optional<ElfImageType> ClassifyDynamicImage(
    std::span<std::byte const> bytes, ElfImageLayout const& layout,
    bool entryIsExecutable, ElfParseExtent extent) noexcept {
  if (layout.entryPoint == 0 || HasSoname(bytes, layout, extent))
    return ElfImageType::SharedObject;
  if (entryIsExecutable)
    return ElfImageType::PositionIndependentExecutable;
  return std::nullopt;
}
}  // namespace upx_killer::engine::elf::parsing::internal
