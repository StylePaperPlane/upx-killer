#include "Core/PE/Imports/Internal/SourceImportLayout.h"

#include "Core/PE/Format/PeFormatTraits.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <string>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::imports::internal;

constexpr std::uint32_t MaximumDescriptors = 4096;
constexpr std::uint32_t MaximumThunks = 16'384;
constexpr std::uint32_t MaximumNameLength = 4096;
constexpr std::uint32_t DescriptorSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);

std::optional<std::size_t> ToRaw(std::span<std::byte const> bytes, PeImageLayout const& layout,
                                 std::uint32_t rva, std::size_t size) noexcept {
  if (rva < layout.sizeOfHeaders && size <= layout.sizeOfHeaders - rva && rva <= bytes.size() &&
      size <= bytes.size() - rva)
    return rva;
  for (auto const& section : layout.sections) {
    if (rva < section.virtualAddress.value) continue;
    auto const delta = rva - section.virtualAddress.value;
    if (delta > section.rawSize || size > section.rawSize - delta) continue;
    auto const raw = static_cast<std::size_t>(section.rawOffset.value) + delta;
    if (raw <= bytes.size() && size <= bytes.size() - raw) return raw;
  }
  return std::nullopt;
}

template <typename T>
bool Read(std::span<std::byte const> bytes, PeImageLayout const& layout, std::uint32_t rva,
          T& value) noexcept {
  auto const raw = ToRaw(bytes, layout, rva, sizeof(T));
  if (!raw) return false;
  std::memcpy(&value, bytes.data() + *raw, sizeof(T));
  return true;
}

std::optional<std::uint32_t> NameLength(std::span<std::byte const> bytes,
                                        PeImageLayout const& layout,
                                        std::uint32_t rva) noexcept {
  if (rva == 0) return std::nullopt;
  for (std::uint32_t offset = 0; offset < MaximumNameLength; ++offset) {
    if (rva > std::numeric_limits<std::uint32_t>::max() - offset) return std::nullopt;
    char value{};
    if (!Read(bytes, layout, rva + offset, value)) return std::nullopt;
    if (value == '\0') return offset != 0 ? std::optional{offset + 1} : std::nullopt;
  }
  return std::nullopt;
}

bool HasImportName(std::span<std::byte const> bytes, PeImageLayout const& layout,
                   std::uint64_t thunk, std::vector<ImportRange>& ranges,
                   ImportSymbol& symbol) noexcept {
  if (thunk > std::numeric_limits<std::uint32_t>::max() - sizeof(WORD)) return false;
  WORD hint{};
  auto const name = static_cast<std::uint32_t>(thunk) + static_cast<std::uint32_t>(sizeof(hint));
  if (!Read(bytes, layout, static_cast<std::uint32_t>(thunk), hint)) return false;
  auto const length = NameLength(bytes, layout, name);
  if (!length || *length > std::numeric_limits<std::uint32_t>::max() - name) return false;
  ranges.push_back({static_cast<std::uint32_t>(thunk), name + *length});
  symbol.hint = hint;
  std::string value;
  value.reserve(*length - 1);
  for (std::uint32_t index = 0; index + 1 < *length; ++index) {
    char character{};
    if (!Read(bytes, layout, name + index, character)) return false;
    value.push_back(character);
  }
  symbol.name = std::move(value);
  return true;
}

bool AddThunkRanges(std::span<std::byte const> bytes, PeImageLayout const& layout,
                    IMAGE_IMPORT_DESCRIPTOR const& descriptor, std::size_t pointerSize,
                    std::uint64_t ordinalFlag, std::vector<ImportRange>& ranges,
                    std::uint32_t& totalThunks,
                    std::string const& moduleName,
                    std::vector<ImportProviderHint>& providers) noexcept {
  if (descriptor.FirstThunk == 0) return false;
  auto const lookup =
      descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
  for (std::uint32_t index = 0; index < MaximumThunks; ++index) {
    auto const offset = static_cast<std::uint64_t>(index) * pointerSize;
    if (offset + pointerSize > std::numeric_limits<std::uint32_t>::max() - lookup ||
        offset + pointerSize > std::numeric_limits<std::uint32_t>::max() - descriptor.FirstThunk)
      return false;
    std::uint64_t lookupValue{};
    std::uint64_t firstThunkValue{};
    auto const lookupRva = lookup + static_cast<std::uint32_t>(offset);
    auto const firstThunkRva = descriptor.FirstThunk + static_cast<std::uint32_t>(offset);
    if (pointerSize == sizeof(std::uint32_t)) {
      std::uint32_t narrowLookup{}, narrowFirstThunk{};
      if (!Read(bytes, layout, lookupRva, narrowLookup) ||
          !Read(bytes, layout, firstThunkRva, narrowFirstThunk))
        return false;
      lookupValue = narrowLookup;
      firstThunkValue = narrowFirstThunk;
    } else {
      if (!Read(bytes, layout, lookupRva, lookupValue) ||
          !Read(bytes, layout, firstThunkRva, firstThunkValue))
        return false;
    }
    if (lookupValue == 0) {
      if (firstThunkValue != 0 || index == 0) return false;
      auto const length = static_cast<std::uint32_t>(offset + pointerSize);
      ranges.push_back({descriptor.FirstThunk, descriptor.FirstThunk + length});
      if (lookup != descriptor.FirstThunk) ranges.push_back({lookup, lookup + length});
      return true;
    }
    if (++totalThunks > MaximumThunks) return false;
    if (firstThunkValue == 0) return false;
    ImportSymbol symbol{};
    if ((lookupValue & ordinalFlag) != 0) {
      if ((lookupValue & 0xffffu) == 0) return false;
      symbol.ordinal = static_cast<std::uint16_t>(lookupValue & 0xffffu);
    } else if (!HasImportName(bytes, layout, lookupValue, ranges, symbol)) {
      return false;
    }
    providers.push_back({firstThunkRva, moduleName, std::move(symbol)});
  }
  return false;
}
}  // namespace

namespace upx_killer::engine::pe::imports::internal {
SourceImportLayoutResult SourceImportLayout::Analyze(std::span<std::byte const> sourceBytes,
                                                     PeImageLayout const& layout) noexcept {
  try {
    auto const directory = layout.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.address.value == 0 && directory.size == 0) return {true, {}};
    if (directory.address.value == 0 || directory.size < 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
        directory.address.value > layout.sizeOfImage ||
        directory.size > layout.sizeOfImage - directory.address.value)
      return {};
    auto const pointerSize = layout.format == PeFormat::Pe32 ? format::Pe32Traits::PointerSize
                                                             : format::Pe64Traits::PointerSize;
    auto const ordinalFlag = layout.format == PeFormat::Pe32
                                 ? static_cast<std::uint64_t>(format::Pe32Traits::OrdinalFlag)
                                 : format::Pe64Traits::OrdinalFlag;
    auto const limit = std::min(directory.size / DescriptorSize, MaximumDescriptors);
    std::vector<ImportRange> ranges;
    std::vector<ImportProviderHint> providers;
    std::uint32_t totalThunks{};
    bool terminated{};
    for (std::uint32_t index = 0; index < limit; ++index) {
      auto const rva = directory.address.value + index * DescriptorSize;
      IMAGE_IMPORT_DESCRIPTOR descriptor{};
      if (!Read(sourceBytes, layout, rva, descriptor)) return {};
      if (descriptor.OriginalFirstThunk == 0 && descriptor.TimeDateStamp == 0 &&
          descriptor.ForwarderChain == 0 && descriptor.Name == 0 && descriptor.FirstThunk == 0) {
        ranges.push_back(
            {directory.address.value, rva + static_cast<std::uint32_t>(sizeof(descriptor))});
        terminated = index != 0;
        break;
      }
      auto const nameLength = NameLength(sourceBytes, layout, descriptor.Name);
      std::string moduleName;
      if (nameLength) {
        moduleName.reserve(*nameLength - 1);
        for (std::uint32_t character = 0; character + 1 < *nameLength; ++character) {
          char value{};
          if (!Read(sourceBytes, layout, descriptor.Name + character, value)) return {};
          moduleName.push_back(value);
        }
      }
      if (!nameLength ||
          moduleName.find('.') == std::string::npos ||
          *nameLength > std::numeric_limits<std::uint32_t>::max() - descriptor.Name ||
          !AddThunkRanges(sourceBytes, layout, descriptor, pointerSize, ordinalFlag, ranges,
                          totalThunks, moduleName, providers))
        return {};
      ranges.push_back({descriptor.Name, descriptor.Name + *nameLength});
    }
    if (!terminated) return {};
    std::sort(ranges.begin(), ranges.end(),
              [](auto const& left, auto const& right) { return left.begin < right.begin; });
    return {true, std::move(ranges), std::move(providers)};
  } catch (...) {
    return {};
  }
}
}  // namespace upx_killer::engine::pe::imports::internal
