#include "Core/PE/Exports/ExportDirectoryAnalyzer.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::exports;

constexpr std::uint32_t MaximumExports = 1u << 20;
constexpr std::size_t MaximumStringLength = 64u * 1024u;

bool Fits(std::size_t offset, std::size_t size, std::size_t limit) noexcept {
  return offset <= limit && size <= limit - offset;
}

template <typename T>
bool Read(std::span<std::byte const> bytes, std::uint32_t rva, T& value) noexcept {
  if (!Fits(rva, sizeof(T), bytes.size())) return false;
  std::memcpy(&value, bytes.data() + rva, sizeof(T));
  return true;
}

bool ReadString(std::span<std::byte const> bytes, std::uint32_t rva,
                std::string& value) noexcept {
  if (rva >= bytes.size()) return false;
  auto const limit = std::min(bytes.size(), static_cast<std::size_t>(rva) + MaximumStringLength);
  auto const begin = reinterpret_cast<char const*>(bytes.data() + rva);
  auto const end = reinterpret_cast<char const*>(bytes.data() + limit);
  auto const terminator = std::find(begin, end, '\0');
  if (terminator == end) return false;
  value.assign(begin, terminator);
  return true;
}

bool IsExecutable(PeImageLayout const& layout, std::uint32_t rva) noexcept {
  constexpr std::uint32_t Execute = IMAGE_SCN_MEM_EXECUTE;
  return std::any_of(layout.sections.begin(), layout.sections.end(), [&](PeSection const& section) {
    auto const extent = std::max(section.virtualSize, section.rawSize);
    return rva >= section.virtualAddress.value &&
           rva - section.virtualAddress.value < extent &&
           (section.characteristics & Execute) != 0;
  });
}
}

namespace upx_killer::engine::pe::exports {
ExportDirectoryResult ExportDirectoryAnalyzer::AnalyzeMapped(
    std::span<std::byte const> mappedImage, PeImageLayout const& layout) noexcept {
  try {
    if (mappedImage.size() < layout.sizeOfImage)
      return {std::nullopt, ExportDirectoryError::Truncated};
    auto const& data = layout.directories[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (data.address.value == 0 && data.size == 0)
      return {ExportDirectoryModel{}, ExportDirectoryError::None};
    if (data.address.value == 0 || data.size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
        data.address.value >= layout.sizeOfImage ||
        data.size > layout.sizeOfImage - data.address.value)
      return {std::nullopt, ExportDirectoryError::InvalidDirectory};

    IMAGE_EXPORT_DIRECTORY header{};
    if (!Read(mappedImage, data.address.value, header))
      return {std::nullopt, ExportDirectoryError::Truncated};
    if (header.NumberOfFunctions > MaximumExports || header.NumberOfNames > header.NumberOfFunctions)
      return {std::nullopt, ExportDirectoryError::InvalidDirectory};

    ExportDirectoryModel model{};
    if (header.Name != 0 && !ReadString(mappedImage, header.Name, model.moduleName))
      return {std::nullopt, ExportDirectoryError::Truncated};
    if (header.NumberOfFunctions == 0) return {std::move(model), ExportDirectoryError::None};
    if (header.AddressOfFunctions == 0 ||
        !Fits(header.AddressOfFunctions,
              static_cast<std::size_t>(header.NumberOfFunctions) * sizeof(DWORD), mappedImage.size()) ||
        (header.NumberOfNames != 0 &&
         (header.AddressOfNames == 0 || header.AddressOfNameOrdinals == 0 ||
          !Fits(header.AddressOfNames,
                static_cast<std::size_t>(header.NumberOfNames) * sizeof(DWORD), mappedImage.size()) ||
          !Fits(header.AddressOfNameOrdinals,
                static_cast<std::size_t>(header.NumberOfNames) * sizeof(WORD), mappedImage.size()))))
      return {std::nullopt, ExportDirectoryError::Truncated};

    std::vector<std::optional<std::string>> names(header.NumberOfFunctions);
    for (DWORD index = 0; index < header.NumberOfNames; ++index) {
      DWORD nameRva{};
      WORD ordinalIndex{};
      if (!Read(mappedImage, header.AddressOfNames + index * sizeof(DWORD), nameRva) ||
          !Read(mappedImage, header.AddressOfNameOrdinals + index * sizeof(WORD), ordinalIndex))
        return {std::nullopt, ExportDirectoryError::Truncated};
      if (ordinalIndex >= header.NumberOfFunctions)
        return {std::nullopt, ExportDirectoryError::InvalidOrdinal};
      std::string name;
      if (!ReadString(mappedImage, nameRva, name))
        return {std::nullopt, ExportDirectoryError::Truncated};
      names[ordinalIndex] = std::move(name);
    }

    model.functions.reserve(header.NumberOfFunctions);
    auto const exportEnd = static_cast<std::uint64_t>(data.address.value) + data.size;
    for (DWORD index = 0; index < header.NumberOfFunctions; ++index) {
      DWORD functionRva{};
      if (!Read(mappedImage, header.AddressOfFunctions + index * sizeof(DWORD), functionRva))
        return {std::nullopt, ExportDirectoryError::Truncated};
      auto const ordinal64 = static_cast<std::uint64_t>(header.Base) + index;
      if (ordinal64 > std::numeric_limits<std::uint16_t>::max())
        return {std::nullopt, ExportDirectoryError::InvalidOrdinal};
      ExportedFunction function{};
      function.ordinal = static_cast<std::uint16_t>(ordinal64);
      function.name = std::move(names[index]);
      if (functionRva != 0 && functionRva >= data.address.value && functionRva < exportEnd) {
        std::string forwarder;
        if (!ReadString(mappedImage, functionRva, forwarder) || forwarder.find('.') == std::string::npos)
          return {std::nullopt, ExportDirectoryError::InvalidTarget};
        function.forwarder = std::move(forwarder);
      } else if (functionRva != 0) {
        if (functionRva >= layout.sizeOfImage)
          return {std::nullopt, ExportDirectoryError::InvalidTarget};
        function.target = RelativeVirtualAddress{functionRva};
        if (IsExecutable(layout, functionRva)) model.codeTargets.push_back({functionRva});
      }
      model.functions.push_back(std::move(function));
    }
    std::sort(model.codeTargets.begin(), model.codeTargets.end(),
              [](auto left, auto right) { return left.value < right.value; });
    model.codeTargets.erase(
        std::unique(model.codeTargets.begin(), model.codeTargets.end(),
                    [](auto left, auto right) { return left.value == right.value; }),
        model.codeTargets.end());
    return {std::move(model), ExportDirectoryError::None};
  } catch (...) {
    return {std::nullopt, ExportDirectoryError::InvalidDirectory};
  }
}
}
