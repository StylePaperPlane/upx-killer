#include "Core/PE/Imports/PeExportParser.h"

#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <limits>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe::imports;

constexpr std::uint32_t MaxExports = 65'536;
constexpr std::size_t MaxString = 512;

template <typename T>
bool Read(std::span<std::byte const> bytes, std::uint64_t offset, T& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - static_cast<std::size_t>(offset))
    return false;
  std::memcpy(&value, bytes.data() + static_cast<std::size_t>(offset), sizeof(T));
  return true;
}

bool RvaRange(std::uint32_t rva, std::uint64_t size, std::span<std::byte const> image,
              std::uint32_t& offset) noexcept {
  if (rva > image.size() || size > image.size() - rva) return false;
  offset = rva;
  return true;
}

bool ReadString(std::span<std::byte const> image, std::uint32_t rva, std::string& value) noexcept {
  if (rva >= image.size()) return false;
  auto const* text = reinterpret_cast<char const*>(image.data() + rva);
  auto const remaining = image.size() - rva;
  auto const length = strnlen_s(text, std::min<std::size_t>(remaining, MaxString));
  if (length == 0 || length >= MaxString || length >= remaining) return false;
  value.assign(text, length);
  return true;
}

}

namespace upx_killer::engine::pe::imports {
ExportParseResult PeExportParser::Parse(std::span<std::byte const> image, LoadedAddress base,
                                        std::string moduleName) noexcept {
  try {
    IMAGE_DOS_HEADER dos{};
    if (!Read(image, 0, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
        dos.e_lfanew < sizeof(IMAGE_DOS_HEADER))
      return {{}, ExportParseError::InvalidImage};
    auto const nt = static_cast<std::uint32_t>(dos.e_lfanew);
    DWORD signature{};
    IMAGE_FILE_HEADER file{};
    if (!Read(image, nt, signature) || !Read(image, nt + sizeof(signature), file) ||
        signature != IMAGE_NT_SIGNATURE)
      return {{}, ExportParseError::InvalidImage};
    WORD magic{};
    auto const optional =
        static_cast<std::uint64_t>(nt) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (!Read(image, optional, magic)) return {{}, ExportParseError::Truncated};
    auto const sectionTable = optional + file.SizeOfOptionalHeader;
    auto const sectionBytes =
        static_cast<std::uint64_t>(file.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (file.NumberOfSections == 0 || file.NumberOfSections > 96 || sectionTable > image.size() ||
        sectionBytes > image.size() - sectionTable)
      return {{}, ExportParseError::InvalidImage};
    std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
    for (WORD index = 0; index < file.NumberOfSections; ++index)
      if (!Read(image, sectionTable + index * sizeof(IMAGE_SECTION_HEADER), sections[index]))
        return {{}, ExportParseError::Truncated};
    std::uint32_t directoryRva{};
    std::uint32_t directorySize{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      IMAGE_OPTIONAL_HEADER64 header{};
      if (!Read(image, optional, header) ||
          header.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return {{}, ExportParseError::InvalidDirectory};
      directoryRva = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      directorySize = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      IMAGE_OPTIONAL_HEADER32 header{};
      if (!Read(image, optional, header) ||
          header.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return {{}, ExportParseError::InvalidDirectory};
      directoryRva = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
      directorySize = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    } else
      return {{}, ExportParseError::InvalidImage};
    if (directoryRva == 0 || directorySize < sizeof(IMAGE_EXPORT_DIRECTORY))
      return {{}, ExportParseError::InvalidDirectory};
    std::uint32_t exportOffset{};
    if (!RvaRange(directoryRva, directorySize, image, exportOffset))
      return {{}, ExportParseError::Truncated};
    IMAGE_EXPORT_DIRECTORY directory{};
    if (!Read(image, exportOffset, directory) || directory.NumberOfFunctions > MaxExports ||
        directory.NumberOfNames > MaxExports)
      return {{}, ExportParseError::LimitExceeded};
    auto const functionBytes =
        static_cast<std::uint64_t>(directory.NumberOfFunctions) * sizeof(DWORD);
    auto const nameBytes = static_cast<std::uint64_t>(directory.NumberOfNames) * sizeof(DWORD);
    auto const ordinalBytes = static_cast<std::uint64_t>(directory.NumberOfNames) * sizeof(WORD);
    if (!RvaRange(directory.AddressOfFunctions, functionBytes, image, exportOffset) ||
        !RvaRange(directory.AddressOfNames, nameBytes, image, exportOffset) ||
        !RvaRange(directory.AddressOfNameOrdinals, ordinalBytes, image, exportOffset))
      return {{}, ExportParseError::Truncated};

    std::vector<std::optional<std::string>> names(directory.NumberOfFunctions);
    std::vector<bool> named(directory.NumberOfFunctions);
    for (DWORD index = 0; index < directory.NumberOfNames; ++index) {
      DWORD nameRva{};
      WORD ordinalIndex{};
      if (!Read(image, static_cast<std::uint64_t>(directory.AddressOfNames) + index * sizeof(DWORD),
                nameRva) ||
          !Read(image,
                static_cast<std::uint64_t>(directory.AddressOfNameOrdinals) + index * sizeof(WORD),
                ordinalIndex) ||
          ordinalIndex >= directory.NumberOfFunctions)
        return {{}, ExportParseError::InvalidDirectory};
      std::string name;
      if (!ReadString(image, nameRva, name)) return {{}, ExportParseError::Truncated};
      // Export names are case-sensitive in the PE import contract;
      // preserve the image spelling for the rebuilt import table.
      names[ordinalIndex] = std::move(name);
      named[ordinalIndex] = true;
    }

    std::vector<RuntimeExport> result;
    result.reserve(directory.NumberOfFunctions);
    for (DWORD index = 0; index < directory.NumberOfFunctions; ++index) {
      DWORD functionRva{};
      if (!Read(image,
                static_cast<std::uint64_t>(directory.AddressOfFunctions) + index * sizeof(DWORD),
                functionRva))
        return {{}, ExportParseError::Truncated};
      if (functionRva == 0) continue;
      RuntimeExport exported{};
      exported.moduleName = moduleName;
      exported.ordinal = static_cast<std::uint16_t>(directory.Base + index);
      if (named[index]) exported.name = names[index];
      auto const forwardEnd = static_cast<std::uint64_t>(directoryRva) + directorySize;
      if (functionRva >= directoryRva && functionRva < forwardEnd) {
        std::string forward;
        if (!ReadString(image, functionRva, forward)) return {{}, ExportParseError::Truncated};
        exported.forwarder = std::move(forward);
        exported.executable = false;
        exported.address = {};
      } else {
        if (functionRva >= image.size()) continue;
        exported.address = {base.value + functionRva};
        exported.executable =
            std::any_of(sections.begin(), sections.end(), [&](IMAGE_SECTION_HEADER const& section) {
              auto const extent = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
              return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
                     functionRva >= section.VirtualAddress &&
                     functionRva - section.VirtualAddress < extent;
            });
      }
      result.push_back(std::move(exported));
    }
    return {std::move(result), ExportParseError::None};
  } catch (...) {
    return {{}, ExportParseError::InvalidImage};
  }
}
}
