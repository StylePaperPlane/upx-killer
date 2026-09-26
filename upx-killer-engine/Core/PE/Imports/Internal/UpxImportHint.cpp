#include "Core/PE/Imports/Internal/UpxImportHint.h"
#include "Core/PE/Metadata/EmbeddedOriginalPeHeader.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <set>
#include <string>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::imports::internal;

constexpr std::size_t MaximumDescriptors = 4096;
constexpr std::size_t MaximumSlots = 16'384;
constexpr std::size_t MaximumNameLength = 4096;

template <typename T>
bool Read(std::span<std::byte const> bytes, std::size_t offset, T& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return true;
}

std::optional<std::size_t> ToRaw(std::span<std::byte const> bytes,
                                 PeImageLayout const& layout,
                                 std::uint32_t rva, std::size_t size) noexcept {
  if (rva < layout.sizeOfHeaders && size <= layout.sizeOfHeaders - rva &&
      rva <= bytes.size() && size <= bytes.size() - rva)
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

std::optional<std::string> ReadName(std::span<std::byte const> bytes,
                                    std::size_t begin, std::size_t end) {
  if (begin >= end || end > bytes.size()) return std::nullopt;
  auto const limit = std::min(end, begin + MaximumNameLength);
  std::string value;
  for (auto offset = begin; offset < limit; ++offset) {
    auto const character = static_cast<unsigned char>(bytes[offset]);
    if (character == 0) return value.empty() ? std::nullopt : std::optional{value};
    if (character < 0x20 || character > 0x7e) return std::nullopt;
    value.push_back(static_cast<char>(character));
  }
  return std::nullopt;
}

std::optional<std::vector<ImportProviderHint>> ParseStream(
    std::span<std::byte const> dumped, std::span<std::byte const> sourceBytes,
    PeImageLayout const& source, metadata::EmbeddedOriginalPeHeader const& embedded) {
  auto const sourceImport = source.directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (sourceImport.address.value == 0 || sourceImport.size == 0 ||
      sourceImport.address.value > source.sizeOfImage ||
      sourceImport.size > source.sizeOfImage - sourceImport.address.value)
    return std::nullopt;
  auto const rawImport = ToRaw(sourceBytes, source, sourceImport.address.value,
                               sourceImport.size);
  if (!rawImport) return std::nullopt;
  std::uint32_t streamOffset{};
  if (!Read(dumped, embedded.metadataOffset, streamOffset) || streamOffset == 0)
    return std::nullopt;
  auto const streamRva = static_cast<std::uint64_t>(embedded.firstRva) + streamOffset;
  if (streamRva >= embedded.metadataOffset || streamRva > dumped.size())
    return std::nullopt;
  auto cursor = static_cast<std::size_t>(streamRva);
  auto const pointerSize = source.format == PeFormat::Pe64 ? sizeof(std::uint64_t)
                                                          : sizeof(std::uint32_t);
  std::vector<ImportProviderHint> hints;
  std::set<std::uint32_t> occupied;
  for (std::uint32_t descriptor = 0; descriptor < embedded.importDescriptors; ++descriptor) {
    std::uint32_t nameOffset{}, iatOffset{};
    if (!Read(dumped, cursor, nameOffset) || !Read(dumped, cursor + 4, iatOffset) ||
        nameOffset >= sourceImport.size ||
        static_cast<std::uint64_t>(embedded.firstRva) + iatOffset >= embedded.imageSize)
      return std::nullopt;
    auto const name = ReadName(sourceBytes, *rawImport + nameOffset,
                               *rawImport + sourceImport.size);
    if (!name || name->find('.') == std::string::npos) return std::nullopt;
    cursor += 8;
    std::size_t count{};
    for (;;) {
      if (cursor >= dumped.size() || cursor >= embedded.metadataOffset) return std::nullopt;
      auto const kind = static_cast<std::uint8_t>(dumped[cursor]);
      if (kind == 0) {
        ++cursor;
        if (count == 0) return std::nullopt;
        break;
      }
      if (hints.size() >= MaximumSlots) return std::nullopt;
      ImportSymbol symbol{};
      if (kind == 1) {
        auto const value = ReadName(dumped, cursor + 1, embedded.metadataOffset);
        if (!value) return std::nullopt;
        symbol.name = *value;
        cursor += 1 + value->size() + 1;
      } else if (kind == 0xff) {
        std::uint16_t ordinal{};
        if (!Read(dumped, cursor + 1, ordinal) || ordinal == 0) return std::nullopt;
        symbol.ordinal = ordinal;
        cursor += 3;
      } else if (kind == 0xfe) {
        std::uint32_t sourceOffset{};
        if (!Read(dumped, cursor + 1, sourceOffset) ||
            sourceOffset > sourceImport.size ||
            pointerSize > sourceImport.size - sourceOffset)
          return std::nullopt;
        auto const raw = *rawImport + sourceOffset;
        std::uint64_t thunk{};
        if (pointerSize == sizeof(std::uint64_t)) {
          if (!Read(sourceBytes, raw, thunk) || (thunk & (1ull << 63)) == 0)
            return std::nullopt;
        } else {
          std::uint32_t narrow{};
          if (!Read(sourceBytes, raw, narrow) || (narrow & (1u << 31)) == 0)
            return std::nullopt;
          thunk = narrow;
        }
        if ((thunk & 0xffffu) == 0) return std::nullopt;
        symbol.ordinal = static_cast<std::uint16_t>(thunk & 0xffffu);
        cursor += 5;
      } else {
        return std::nullopt;
      }
      auto const slot = static_cast<std::uint64_t>(embedded.firstRva) + iatOffset +
                        count * pointerSize;
      if (slot > embedded.imageSize || pointerSize > embedded.imageSize - slot ||
          slot % sizeof(std::uint32_t) != 0 ||
          !occupied.insert(static_cast<std::uint32_t>(slot)).second)
        return std::nullopt;
      hints.push_back({static_cast<std::uint32_t>(slot), *name, std::move(symbol)});
      ++count;
    }
    if (cursor > embedded.metadataOffset) return std::nullopt;
  }
  std::uint32_t terminator{};
  if (!Read(dumped, cursor, terminator) || terminator != 0)
    return std::nullopt;
  return hints;
}
}

namespace upx_killer::engine::pe::imports::internal {
std::vector<ImportProviderHint> UpxImportHint::Analyze(
    std::span<std::byte const> dumpedBytes,
    std::span<std::byte const> sourceBytes,
    PeImageLayout const& sourceLayout,
    RelativeVirtualAddress recoveredEntryPoint) noexcept {
  try {
    if (sourceLayout.entryPoint.value == recoveredEntryPoint.value ||
        sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT].address.value != 0 ||
        sourceLayout.directories[IMAGE_DIRECTORY_ENTRY_IAT].size != 0)
      return {};
    auto embedded = metadata::FindEmbeddedOriginalPeHeader(
        dumpedBytes, sourceLayout, recoveredEntryPoint);
    if (!embedded) return {};
    auto hints = ParseStream(dumpedBytes, sourceBytes, sourceLayout, *embedded);
    return hints ? std::move(*hints) : std::vector<ImportProviderHint>{};
  } catch (...) {
    return {};
  }
}
}
