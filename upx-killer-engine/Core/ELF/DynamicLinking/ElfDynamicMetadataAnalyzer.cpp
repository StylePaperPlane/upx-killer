#include "Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.h"

#include <algorithm>
#include <optional>
#include <unordered_map>

namespace {
using namespace upx_killer::engine::elf;
using namespace upx_killer::engine::elf::dynamic_linking;

std::uint64_t ReadU64(std::span<std::byte const> bytes,
                      std::size_t offset) noexcept {
  std::uint64_t value{};
  if (offset > bytes.size() || 8 > bytes.size() - offset) return 0;
  for (std::size_t index = 0; index < 8; ++index)
    value |= static_cast<std::uint64_t>(
                 std::to_integer<std::uint8_t>(bytes[offset + index]))
             << (index * 8);
  return value;
}

std::optional<std::uint64_t> FileOffsetFor(
    ElfImageLayout const& layout, std::uint64_t address,
    std::uint64_t size) noexcept {
  for (auto const& header : layout.programHeaders) {
    if (header.type != 1 || address < header.virtualAddress ||
        size > header.fileSize ||
        address - header.virtualAddress > header.fileSize - size)
      continue;
    return header.fileOffset + address - header.virtualAddress;
  }
  return std::nullopt;
}
}

namespace upx_killer::engine::elf::dynamic_linking {
ElfDynamicMetadataResult ElfDynamicMetadataAnalyzer::Analyze(
    std::span<std::byte const> image,
    ElfImageLayout const& layout) noexcept {
  try {
    auto dynamic = std::find_if(layout.programHeaders.begin(),
                                layout.programHeaders.end(),
                                [](auto const& header) {
                                  return header.type == 2;
                                });
    if (dynamic == layout.programHeaders.end()) return {true, false, {}, {}};
    if (dynamic->fileSize < 16 || dynamic->fileSize % 16 != 0 ||
        dynamic->fileOffset > image.size() ||
        dynamic->fileSize > image.size() - dynamic->fileOffset)
      return {false, true, {}, "elf.dynamic.range_invalid"};
    std::unordered_map<std::uint64_t, std::uint64_t> tags;
    bool terminated{};
    for (std::uint64_t cursor = 0; cursor < dynamic->fileSize; cursor += 16) {
      auto const offset = static_cast<std::size_t>(dynamic->fileOffset + cursor);
      auto const tag = ReadU64(image, offset);
      auto const value = ReadU64(image, offset + 8);
      if (tag == 0) {
        terminated = true;
        break;
      }
      tags.try_emplace(tag, value);
    }
    if (!terminated || !tags.contains(5) || !tags.contains(6) ||
        !tags.contains(10) || !tags.contains(11) || tags.at(10) == 0 ||
        tags.at(11) != 24)
      return {false, true, {}, "elf.dynamic.required_tags_missing"};

    std::vector<ElfDynamicSection> sections;
    auto add = [&](std::string name, std::uint32_t type,
                   std::uint64_t address, std::uint64_t size,
                   std::uint64_t alignment, std::uint64_t entrySize,
                   std::string link) {
      if (size == 0) return true;
      auto const offset = FileOffsetFor(layout, address, size);
      if (!offset || *offset > image.size() || size > image.size() - *offset)
        return false;
      sections.push_back({std::move(name), type, 2, address, *offset, size,
                          alignment, entrySize, std::move(link)});
      return true;
    };
    auto const stringAddress = tags.at(5);
    auto const symbolAddress = tags.at(6);
    auto const stringSize = tags.at(10);
    if (!add(".dynstr", 3, stringAddress, stringSize, 1, 0, {}))
      return {false, true, {}, "elf.dynamic.string_table_invalid"};
    auto const symbolSize = stringAddress > symbolAddress
                                ? stringAddress - symbolAddress
                                : 0;
    if (symbolSize == 0 || symbolSize % 24 != 0 ||
        !add(".dynsym", 11, symbolAddress, symbolSize, 8, 24, ".dynstr"))
      return {false, true, {}, "elf.dynamic.symbol_table_invalid"};
    if (tags.contains(7) && tags.contains(8) &&
        !add(".rela.dyn", 4, tags.at(7), tags.at(8), 8,
             tags.contains(9) ? tags.at(9) : 24, ".dynsym"))
      return {false, true, {}, "elf.dynamic.relocations_invalid"};
    if (tags.contains(23) && tags.contains(2) &&
        !add(".rela.plt", 4, tags.at(23), tags.at(2), 8, 24, ".dynsym"))
      return {false, true, {}, "elf.dynamic.plt_relocations_invalid"};
    return {true, true, std::move(sections), {}};
  } catch (...) {
    return {false, true, {}, "elf.dynamic.analysis_failed"};
  }
}
}  // namespace upx_killer::engine::elf::dynamic_linking
