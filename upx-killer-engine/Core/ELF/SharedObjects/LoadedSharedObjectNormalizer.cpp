#include "Core/ELF/SharedObjects/LoadedSharedObjectNormalizer.h"

#include "Core/ELF/Format/Internal/ElfClassTraits.h"

#include <algorithm>
#include <array>
#include <limits>

namespace {
using namespace upx_killer::engine::elf;

constexpr std::uint32_t LoadProgramHeader = 1;
constexpr std::uint32_t DynamicProgramHeader = 2;
constexpr std::uint64_t NullTag = 0;
constexpr std::uint64_t DebugTag = 21;
constexpr std::uint64_t InitTag = 12;
constexpr std::array<std::uint64_t, 16> AddressTags{
    3, 4, 5, 6, 7, 12, 13, 17, 23, 25, 26,
    0x6ffffef5, 0x6ffffff0, 0x6ffffffc, 0x6ffffffe, 0x6ffffff9};

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

bool WriteUnsigned(std::span<std::byte> bytes, std::size_t offset,
                   std::size_t width, std::uint64_t value) noexcept {
  if ((width != 4 && width != 8) || offset > bytes.size() ||
      width > bytes.size() - offset ||
      (width == 4 && value > std::numeric_limits<std::uint32_t>::max()))
    return false;
  for (std::size_t index = 0; index < width; ++index)
    bytes[offset + index] =
        static_cast<std::byte>((value >> (index * 8)) & 0xff);
  return true;
}
}  // namespace

namespace upx_killer::engine::elf::shared_objects {
SharedObjectNormalizationResult LoadedSharedObjectNormalizer::Normalize(
    CapturedElfImage& captured,
    ElfImageLayout const& packedLayout) noexcept {
  try {
    if (captured.layout.imageType != ElfImageType::SharedObject)
      return {false, "elf.shared_object.normalize_kind_invalid"};
    auto const& traits = internal::GetElfClassTraits(captured.layout.imageClass);
    auto const dynamic = std::find_if(
        captured.layout.programHeaders.begin(),
        captured.layout.programHeaders.end(),
        [](auto const& header) { return header.type == DynamicProgramHeader; });
    if (dynamic == captured.layout.programHeaders.end())
      return {true, {}};
    auto const executableLoad = std::find_if(
        captured.layout.programHeaders.begin(),
        captured.layout.programHeaders.end(), [](auto const& header) {
          return header.type == LoadProgramHeader && (header.flags & 1U) != 0;
        });
    if (executableLoad == captured.layout.programHeaders.end())
      return {false, "elf.shared_object.executable_segment_missing"};
    auto containingLoad = std::find_if(
        captured.layout.programHeaders.begin(),
        captured.layout.programHeaders.end(), [&](auto const& header) {
          return header.type == LoadProgramHeader &&
                 dynamic->virtualAddress >= header.virtualAddress &&
                 dynamic->fileSize <= header.fileSize &&
                 dynamic->virtualAddress - header.virtualAddress <=
                     header.fileSize - dynamic->fileSize;
        });
    if (containingLoad == captured.layout.programHeaders.end())
      return {false, "elf.shared_object.dynamic_segment_invalid"};
    auto const loadIndex = static_cast<std::size_t>(
        containingLoad - captured.layout.programHeaders.begin());
    auto segment = std::find_if(
        captured.segments.begin(), captured.segments.end(),
        [&](auto const& candidate) {
          return candidate.programHeaderIndex == loadIndex;
        });
    if (segment == captured.segments.end())
      return {false, "elf.shared_object.dynamic_segment_missing"};
    auto const dynamicOffset = static_cast<std::size_t>(
        dynamic->virtualAddress - containingLoad->virtualAddress);
    auto bytes = std::span<std::byte>{segment->fileBytes};
    if (dynamicOffset > bytes.size() ||
        dynamic->fileSize > bytes.size() - dynamicOffset ||
        dynamic->fileSize % traits.dynamicEntrySize != 0)
      return {false, "elf.shared_object.dynamic_segment_invalid"};
    std::uint64_t maximumRelativeAddress{};
    bool foundLoad{};
    for (auto const& header : captured.layout.programHeaders) {
      if (header.type != LoadProgramHeader) continue;
      if (header.memorySize > std::numeric_limits<std::uint64_t>::max() -
                                  header.virtualAddress)
        return {false, "elf.shared_object.load_range_overflow"};
      maximumRelativeAddress =
          std::max(maximumRelativeAddress,
                   header.virtualAddress + header.memorySize);
      foundLoad = true;
    }
    if (!foundLoad ||
        maximumRelativeAddress >
            std::numeric_limits<std::uint64_t>::max() - captured.loadBias.value)
      return {false, "elf.shared_object.load_range_overflow"};
    auto const maximumAddress =
        captured.loadBias.value + maximumRelativeAddress;
    bool terminated{};
    for (std::uint64_t cursor = 0; cursor < dynamic->fileSize;
         cursor += traits.dynamicEntrySize) {
      auto const offset = dynamicOffset + static_cast<std::size_t>(cursor);
      auto const tag = ReadUnsigned(bytes, offset, traits.addressWidth);
      auto value = ReadUnsigned(bytes, offset + traits.addressWidth,
                                traits.addressWidth);
      if (tag == NullTag) {
        terminated = true;
        break;
      }
      if (tag == DebugTag) {
        value = 0;
      } else if (tag == InitTag && value == packedLayout.entryPoint) {
        value = executableLoad->virtualAddress;
      } else if (std::find(AddressTags.begin(), AddressTags.end(), tag) !=
                     AddressTags.end() &&
                 value >= captured.loadBias.value && value < maximumAddress) {
        value -= captured.loadBias.value;
      }
      if (!WriteUnsigned(bytes, offset + traits.addressWidth,
                         traits.addressWidth, value))
        return {false, "elf.shared_object.dynamic_value_invalid"};
    }
    return terminated
               ? SharedObjectNormalizationResult{true, {}}
               : SharedObjectNormalizationResult{
                     false, "elf.shared_object.dynamic_terminator_missing"};
  } catch (...) {
    return {false, "elf.shared_object.normalization_failed"};
  }
}
}  // namespace upx_killer::engine::elf::shared_objects
