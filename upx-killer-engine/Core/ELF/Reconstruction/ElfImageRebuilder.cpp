#include "Core/ELF/Reconstruction/ElfImageRebuilder.h"
#include "Core/ELF/DynamicLinking/ElfDynamicMetadataAnalyzer.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <unordered_map>

namespace {
using namespace upx_killer::engine::elf;

constexpr std::uint32_t LoadProgramHeader = 1;
constexpr std::uint32_t DynamicProgramHeader = 2;
constexpr std::uint32_t InterpreterProgramHeader = 3;
constexpr std::uint32_t TlsProgramHeader = 7;
constexpr std::uint64_t AllocSectionFlag = 0x2;
constexpr std::uint64_t WriteSectionFlag = 0x1;
constexpr std::uint64_t ExecuteSectionFlag = 0x4;
constexpr std::uint32_t ProgramBitsSection = 1;
constexpr std::uint32_t StringTableSection = 3;
constexpr std::uint32_t NoBitsSection = 8;
constexpr std::uint32_t DynamicSection = 6;
constexpr std::uint32_t Elf64SectionHeaderSize = 64;

struct Section {
  std::string name;
  std::uint32_t type{};
  std::uint64_t flags{};
  std::uint64_t address{};
  std::uint64_t offset{};
  std::uint64_t size{};
  std::uint64_t alignment{1};
  std::uint64_t entrySize{};
  std::string linkSection;
};

bool AddOverflows(std::uint64_t left, std::uint64_t right) noexcept {
  return right > std::numeric_limits<std::uint64_t>::max() - left;
}

std::uint64_t AlignUp(std::uint64_t value, std::uint64_t alignment) noexcept {
  if (alignment <= 1) return value;
  auto const remainder = value % alignment;
  if (remainder == 0) return value;
  auto const increment = alignment - remainder;
  return AddOverflows(value, increment) ? 0 : value + increment;
}

template <typename T>
void Write(std::vector<std::byte>& bytes, std::size_t offset, T value) {
  for (std::size_t index = 0; index < sizeof(T); ++index)
    bytes[offset + index] = static_cast<std::byte>((value >> (index * 8)) & 0xff);
}

std::string LoadName(ElfProgramHeader const& header, std::size_t ordinal) {
  std::string base;
  if ((header.flags & 1) != 0) base = ".text";
  else if ((header.flags & 2) != 0) base = ".data";
  else base = ".rodata";
  if (ordinal != 0) base += "." + std::to_string(ordinal);
  return base;
}
}

namespace upx_killer::engine::elf {
ElfRebuildResult ElfImageRebuilder::Rebuild(
    CapturedElfImage const& captured,
    std::uint64_t maximumImageSize) noexcept {
  try {
    if (maximumImageSize < 64 || captured.layout.programHeaders.empty())
      return {{}, "elf.reconstruction.invalid_input"};
    std::unordered_map<std::size_t, std::span<std::byte const>> segments;
    for (auto const& segment : captured.segments)
      segments.emplace(segment.programHeaderIndex, segment.fileBytes);

    std::uint64_t fileSize{};
    for (std::size_t index = 0; index < captured.layout.programHeaders.size(); ++index) {
      auto const& header = captured.layout.programHeaders[index];
      if (header.type != LoadProgramHeader || header.fileSize == 0) continue;
      auto found = segments.find(index);
      if (found == segments.end() || found->second.size() != header.fileSize ||
          AddOverflows(header.fileOffset, header.fileSize))
        return {{}, "elf.reconstruction.segment_missing"};
      fileSize = std::max(fileSize, header.fileOffset + header.fileSize);
    }
    if (fileSize < 64 || fileSize > maximumImageSize ||
        fileSize > std::numeric_limits<std::size_t>::max())
      return {{}, "elf.reconstruction.size_invalid"};
    std::vector<std::byte> bytes(static_cast<std::size_t>(fileSize));
    for (auto const& [index, data] : segments) {
      auto const& header = captured.layout.programHeaders[index];
      std::copy(data.begin(), data.end(),
                bytes.begin() + static_cast<std::size_t>(header.fileOffset));
    }

    std::vector<Section> sections;
    sections.push_back({});
    std::size_t textOrdinal{}, dataOrdinal{}, rodataOrdinal{};
    for (auto const& header : captured.layout.programHeaders) {
      if (header.type != LoadProgramHeader) continue;
      auto& ordinal = (header.flags & 1) != 0 ? textOrdinal
                      : (header.flags & 2) != 0 ? dataOrdinal
                                                : rodataOrdinal;
      auto flags = AllocSectionFlag;
      if ((header.flags & 1) != 0) flags |= ExecuteSectionFlag;
      if ((header.flags & 2) != 0) flags |= WriteSectionFlag;
      if (header.fileSize != 0) {
        sections.push_back({LoadName(header, ordinal++), ProgramBitsSection, flags,
                            header.virtualAddress, header.fileOffset,
                            header.fileSize,
                            std::max<std::uint64_t>(1, header.alignment), 0, {}});
      }
      if (header.memorySize > header.fileSize) {
        sections.push_back({".bss", NoBitsSection,
                            flags | WriteSectionFlag,
                            header.virtualAddress + header.fileSize,
                            header.fileOffset + header.fileSize,
                            header.memorySize - header.fileSize,
                            std::max<std::uint64_t>(1, header.alignment), 0, {}});
      }
    }
    for (auto const& header : captured.layout.programHeaders) {
      if (header.fileSize == 0) continue;
      if (header.type == InterpreterProgramHeader)
        sections.push_back({".interp", ProgramBitsSection, AllocSectionFlag,
                            header.virtualAddress, header.fileOffset,
                            header.fileSize, 1, 0, {}});
      else if (header.type == DynamicProgramHeader)
        sections.push_back({".dynamic", DynamicSection,
                            AllocSectionFlag | WriteSectionFlag,
                            header.virtualAddress, header.fileOffset,
                            header.fileSize, 8, 16, ".dynstr"});
      else if (header.type == TlsProgramHeader)
        sections.push_back({".tdata", ProgramBitsSection,
                            AllocSectionFlag | WriteSectionFlag,
                            header.virtualAddress, header.fileOffset,
                            header.fileSize,
                            std::max<std::uint64_t>(1, header.alignment), 0, {}});
    }

    auto dynamicMetadata =
        dynamic_linking::ElfDynamicMetadataAnalyzer::Analyze(bytes,
                                                              captured.layout);
    if (!dynamicMetadata.valid)
      return {{}, std::move(dynamicMetadata.detailCode)};
    for (auto const& dynamicSection : dynamicMetadata.sections) {
      sections.push_back({dynamicSection.name,
                          dynamicSection.type,
                          dynamicSection.flags,
                          dynamicSection.address,
                          dynamicSection.fileOffset,
                          dynamicSection.size,
                          dynamicSection.alignment,
                          dynamicSection.entrySize,
                          dynamicSection.linkSection});
    }

    std::string names(1, '\0');
    std::vector<std::uint32_t> nameOffsets;
    nameOffsets.reserve(sections.size() + 1);
    nameOffsets.push_back(0);
    for (std::size_t index = 1; index < sections.size(); ++index) {
      nameOffsets.push_back(static_cast<std::uint32_t>(names.size()));
      names += sections[index].name;
      names.push_back('\0');
    }
    auto const shstrNameOffset = static_cast<std::uint32_t>(names.size());
    names += ".shstrtab";
    names.push_back('\0');
    auto const shstrOffset = AlignUp(fileSize, 8);
    auto const sectionHeaderOffset = AlignUp(shstrOffset + names.size(), 8);
    auto const sectionCount = sections.size() + 1;
    auto const finalSize = sectionHeaderOffset + sectionCount * Elf64SectionHeaderSize;
    if (shstrOffset == 0 || sectionHeaderOffset == 0 ||
        finalSize > maximumImageSize ||
        finalSize > std::numeric_limits<std::size_t>::max() ||
        sectionCount > std::numeric_limits<std::uint16_t>::max())
      return {{}, "elf.reconstruction.section_table_too_large"};
    bytes.resize(static_cast<std::size_t>(finalSize));
    std::memcpy(bytes.data() + shstrOffset, names.data(), names.size());

    auto writeSection = [&](std::size_t index, std::uint32_t name,
                            Section const& section) {
      auto const offset = static_cast<std::size_t>(
          sectionHeaderOffset + index * Elf64SectionHeaderSize);
      Write(bytes, offset, name);
      Write(bytes, offset + 4, section.type);
      Write(bytes, offset + 8, section.flags);
      Write(bytes, offset + 16, section.address);
      Write(bytes, offset + 24, section.offset);
      Write(bytes, offset + 32, section.size);
      if (!section.linkSection.empty()) {
        auto const linked = std::find_if(
            sections.begin(), sections.end(), [&](auto const& candidate) {
              return candidate.name == section.linkSection;
            });
        if (linked != sections.end())
          Write<std::uint32_t>(
              bytes, offset + 40,
              static_cast<std::uint32_t>(linked - sections.begin()));
      }
      Write<std::uint64_t>(bytes, offset + 48, section.alignment);
      Write(bytes, offset + 56, section.entrySize);
    };
    for (std::size_t index = 1; index < sections.size(); ++index)
      writeSection(index, nameOffsets[index], sections[index]);
    writeSection(sections.size(), shstrNameOffset,
                 {".shstrtab", StringTableSection, 0, 0, shstrOffset,
                  names.size(), 1, 0, {}});

    Write(bytes, 40, sectionHeaderOffset);
    Write<std::uint16_t>(bytes, 58, Elf64SectionHeaderSize);
    Write<std::uint16_t>(bytes, 60, static_cast<std::uint16_t>(sectionCount));
    Write<std::uint16_t>(bytes, 62, static_cast<std::uint16_t>(sections.size()));
    return {std::move(bytes), {}};
  } catch (...) {
    return {{}, "elf.reconstruction.failed"};
  }
}
}  // namespace upx_killer::engine::elf
