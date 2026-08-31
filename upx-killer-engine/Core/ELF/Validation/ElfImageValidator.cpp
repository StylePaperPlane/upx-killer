#include "Core/ELF/Validation/ElfImageValidator.h"
#include "Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.h"

#include <limits>
#include <type_traits>

namespace upx_killer::engine::elf {
ElfValidationResult ElfImageValidator::Validate(
    std::span<std::byte const> bytes) noexcept {
  auto parsed = ElfParser::Parse(bytes);
  if (!parsed.layout) return {false, "elf.validation.header_invalid"};
  for (auto const& header : parsed.layout->programHeaders) {
    if (header.type != 1 || header.fileSize == 0) continue;
    if (header.fileOffset > bytes.size() ||
        header.fileSize > bytes.size() - header.fileOffset)
      return {false, "elf.validation.segment_out_of_range"};
  }
  auto dynamic = dynamic_linking::ElfDynamicMetadataAnalyzer::Analyze(
      bytes, *parsed.layout);
  if (!dynamic.valid) return {false, std::move(dynamic.detailCode)};
  std::uint64_t sectionOffset{};
  std::uint16_t sectionSize{}, sectionCount{}, stringIndex{};
  auto read = [&](std::size_t offset, auto& value) {
    using T = std::remove_reference_t<decltype(value)>;
    if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
    value = 0;
    for (std::size_t index = 0; index < sizeof(T); ++index)
      value |= static_cast<T>(std::to_integer<std::uint8_t>(bytes[offset + index]))
               << (index * 8);
    return true;
  };
  if (!read(40, sectionOffset) || !read(58, sectionSize) ||
      !read(60, sectionCount) || !read(62, stringIndex) || sectionSize != 64 ||
      sectionCount == 0 || stringIndex >= sectionCount ||
      sectionOffset > bytes.size() ||
      static_cast<std::uint64_t>(sectionSize) * sectionCount >
          bytes.size() - sectionOffset)
    return {false, "elf.validation.sections_invalid"};
  return {true, {}};
}
}  // namespace upx_killer::engine::elf
