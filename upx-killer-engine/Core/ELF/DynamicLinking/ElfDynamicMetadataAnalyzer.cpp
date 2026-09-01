#include "Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.h"
#include "Core/ELF/Format/Internal/ElfClassTraits.h"

#include <algorithm>
#include <optional>
#include <unordered_map>

namespace {
using namespace upx_killer::engine::elf;
using namespace upx_killer::engine::elf::dynamic_linking;

std::uint64_t ReadUnsigned(std::span<std::byte const> bytes,
                           std::size_t offset,
                           std::size_t width) noexcept {
  std::uint64_t value{};
  if ((width != 4 && width != 8) || offset > bytes.size() ||
      width > bytes.size() - offset)
    return 0;
  for (std::size_t index = 0; index < width; ++index)
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
    auto const& traits = internal::GetElfClassTraits(layout.imageClass);
    auto dynamic = std::find_if(layout.programHeaders.begin(),
                                layout.programHeaders.end(),
                                [](auto const& header) {
                                  return header.type == 2;
                                });
    if (dynamic == layout.programHeaders.end()) return {true, false, {}, {}};
    if (dynamic->fileSize < traits.dynamicEntrySize ||
        dynamic->fileSize % traits.dynamicEntrySize != 0 ||
        dynamic->fileOffset > image.size() ||
        dynamic->fileSize > image.size() - dynamic->fileOffset)
      return {false, true, {}, "elf.dynamic.range_invalid"};
    std::unordered_map<std::uint64_t, std::uint64_t> tags;
    bool terminated{};
    for (std::uint64_t cursor = 0; cursor < dynamic->fileSize;
         cursor += traits.dynamicEntrySize) {
      auto const offset = static_cast<std::size_t>(dynamic->fileOffset + cursor);
      auto const tag = ReadUnsigned(image, offset, traits.addressWidth);
      auto const value =
          ReadUnsigned(image, offset + traits.addressWidth,
                       traits.addressWidth);
      if (tag == 0) {
        terminated = true;
        break;
      }
      tags.try_emplace(tag, value);
    }
    if (!terminated || !tags.contains(5) || !tags.contains(6) ||
        !tags.contains(10) || !tags.contains(11) || tags.at(10) == 0 ||
        tags.at(11) != traits.symbolEntrySize)
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
    if (symbolSize == 0 || symbolSize % traits.symbolEntrySize != 0 ||
        !add(".dynsym", 11, symbolAddress, symbolSize, traits.addressWidth,
             traits.symbolEntrySize, ".dynstr"))
      return {false, true, {}, "elf.dynamic.symbol_table_invalid"};
    if (tags.contains(7) && tags.contains(8) &&
        (!tags.contains(9) || tags.at(9) != traits.relaEntrySize ||
         !add(".rela.dyn", 4, tags.at(7), tags.at(8), traits.addressWidth,
              traits.relaEntrySize, ".dynsym")))
      return {false, true, {}, "elf.dynamic.relocations_invalid"};
    if (tags.contains(17) && tags.contains(18) &&
        (!tags.contains(19) || tags.at(19) != traits.relEntrySize ||
         !add(".rel.dyn", 9, tags.at(17), tags.at(18), traits.addressWidth,
              traits.relEntrySize, ".dynsym")))
      return {false, true, {}, "elf.dynamic.relocations_invalid"};
    if (tags.contains(23) && tags.contains(2)) {
      auto const pltKind = tags.contains(20)
                               ? tags.at(20)
                               : (layout.imageClass == ElfClass::Bits32 ? 17 : 7);
      auto const isRela = pltKind == 7;
      auto const isRel = pltKind == 17;
      if ((!isRela && !isRel) ||
          !add(isRela ? ".rela.plt" : ".rel.plt", isRela ? 4U : 9U,
               tags.at(23), tags.at(2), traits.addressWidth,
               isRela ? traits.relaEntrySize : traits.relEntrySize,
               ".dynsym"))
        return {false, true, {}, "elf.dynamic.plt_relocations_invalid"};
    }
    return {true, true, std::move(sections), {}};
  } catch (...) {
    return {false, true, {}, "elf.dynamic.analysis_failed"};
  }
}
}  // namespace upx_killer::engine::elf::dynamic_linking
