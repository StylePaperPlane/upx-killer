#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.h"

#include "Core/ELF/Parsing/ElfParser.h"
#include "Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.h"

#include <algorithm>
#include <limits>

namespace {
using namespace upx_killer;
using elf_host::debugging::LinuxMemoryMapping;

constexpr std::uint32_t LoadProgramHeader = 1;
constexpr std::uint32_t DynamicProgramHeader = 2;
constexpr std::uint32_t ExecuteFlag = 1;

bool RangeCovered(std::vector<LinuxMemoryMapping> const& mappings,
                  std::uint64_t begin, std::uint64_t end,
                  std::uint32_t flags) noexcept {
  auto cursor = begin;
  while (cursor < end) {
    auto found = std::find_if(mappings.begin(), mappings.end(),
                              [&](auto const& mapping) {
                                return mapping.begin <= cursor &&
                                       mapping.end > cursor;
                              });
    if (found == mappings.end() || !found->read ||
        (((flags & ExecuteFlag) != 0) != found->execute) ||
        ((flags & 2u) == 0 && found->write))
      return false;
    cursor = std::min(end, found->end);
  }
  return true;
}

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
}  // namespace

namespace upx_killer::elf_host::debugging {
std::optional<RecoveredElfImage> RecoveredElfImageLocator::Find(
    pid_t pid, engine::elf::ElfImageLayout const& packed) {
  constexpr std::size_t MaximumHeaderBytes = 64 + 128 * 56;
  constexpr std::uint64_t MaximumSearchMappingSize = 16ull << 20;
  auto const mappings = LinuxProcessMemory::ReadMappings(pid);
  for (auto const& mapping : mappings) {
    if (!mapping.read || mapping.end <= mapping.begin) continue;
    auto const mappingSize = mapping.end - mapping.begin;
    if (mapping.path.starts_with('[') && mapping.path != "[stack]") continue;
    auto const searchWholeMapping =
        (mapping.path.empty() || mapping.path == "[stack]") &&
        mappingSize <= MaximumSearchMappingSize;
    auto const bytesToRead = searchWholeMapping
                                 ? mappingSize
                                 : std::min<std::uint64_t>(mappingSize,
                                                           MaximumHeaderBytes);
    if (bytesToRead < 64 ||
        bytesToRead > std::numeric_limits<std::size_t>::max())
      continue;
    std::vector<std::byte> bytes(static_cast<std::size_t>(bytesToRead));
    if (!LinuxProcessMemory::Read(pid, mapping.begin, bytes)) continue;
    for (std::size_t offset = 0; offset + 64 <= bytes.size(); ++offset) {
      if (bytes[offset] != std::byte{0x7f} ||
          bytes[offset + 1] != std::byte{'E'} ||
          bytes[offset + 2] != std::byte{'L'} ||
          bytes[offset + 3] != std::byte{'F'})
        continue;
      auto const available = std::min(MaximumHeaderBytes, bytes.size() - offset);
      auto parsed = engine::elf::ElfParser::Parse(
          std::span<std::byte const>{bytes}.subspan(offset, available),
          engine::elf::ElfParseExtent::LoadedHeaders);
      if (!parsed.layout || !parsed.layout->IsExecutableTarget()) continue;
      if (parsed.layout->entryPoint == packed.entryPoint &&
          parsed.layout->programHeaderCount == packed.programHeaderCount)
        continue;
      std::uint64_t bias{};
      if (parsed.layout->imageType != engine::elf::ElfImageType::Executable) {
        bool foundBias{};
        for (auto const& candidate : mappings) {
          for (auto const& header : parsed.layout->programHeaders) {
            if (header.type != LoadProgramHeader) continue;
            auto const alignedVirtualAddress = header.virtualAddress & ~0xfffull;
            if (candidate.begin < alignedVirtualAddress) continue;
            auto const candidateBias = candidate.begin - alignedVirtualAddress;
            auto const allLoadsCovered = std::all_of(
                parsed.layout->programHeaders.begin(),
                parsed.layout->programHeaders.end(), [&](auto const& load) {
                  return load.type != LoadProgramHeader || load.fileSize == 0 ||
                         RangeCovered(mappings,
                                      candidateBias + load.virtualAddress,
                                      candidateBias + load.virtualAddress +
                                          load.fileSize,
                                      load.flags);
                });
            if (allLoadsCovered) {
              bias = candidateBias;
              foundBias = true;
              break;
            }
          }
          if (foundBias) break;
        }
        if (!foundBias) continue;
      }
      return RecoveredElfImage{std::move(*parsed.layout),
                               mapping.begin + offset, bias};
    }
  }
  return std::nullopt;
}

bool RecoveredElfImageLocator::AllSegmentsReady(
    pid_t pid, RecoveredElfImage const& recovered) {
  auto const mappings = LinuxProcessMemory::ReadMappings(pid);
  for (auto const& header : recovered.layout.programHeaders) {
    if (header.type != LoadProgramHeader || header.fileSize == 0) continue;
    auto const begin = recovered.loadBias + header.virtualAddress;
    auto const end = begin + header.fileSize;
    if (!RangeCovered(mappings, begin, end, header.flags)) return false;
  }
  return true;
}

std::optional<engine::elf::CapturedElfImage> RecoveredElfImageLocator::Capture(
    pid_t pid, RecoveredElfImage const& recovered,
    std::uint64_t maximumSize) {
  engine::elf::CapturedElfImage captured{};
  captured.layout = recovered.layout;
  captured.loadBias.value = recovered.loadBias;
  std::uint64_t total{};
  for (std::size_t index = 0;
       index < recovered.layout.programHeaders.size(); ++index) {
    auto const& header = recovered.layout.programHeaders[index];
    if (header.type != LoadProgramHeader || header.fileSize == 0) continue;
    if (header.fileSize > maximumSize - total ||
        header.fileSize > std::numeric_limits<std::size_t>::max())
      return std::nullopt;
    engine::elf::CapturedElfSegment segment{};
    segment.programHeaderIndex = index;
    segment.fileBytes.resize(static_cast<std::size_t>(header.fileSize));
    if (!LinuxProcessMemory::Read(pid,
                                  recovered.loadBias + header.virtualAddress,
                                  segment.fileBytes))
      return std::nullopt;
    total += header.fileSize;
    captured.segments.push_back(std::move(segment));
  }
  return captured;
}

bool RecoveredElfImageLocator::HasCompleteDynamicLinkage(
    engine::elf::CapturedElfImage const& captured) noexcept {
  auto dynamic = std::find_if(captured.layout.programHeaders.begin(),
                              captured.layout.programHeaders.end(),
                              [](auto const& header) {
                                return header.type == DynamicProgramHeader;
                              });
  if (dynamic == captured.layout.programHeaders.end()) return true;
  if (dynamic->fileSize < 16 || dynamic->fileSize % 16 != 0) return false;
  for (auto const& segment : captured.segments) {
    if (segment.programHeaderIndex >= captured.layout.programHeaders.size())
      continue;
    auto const& load =
        captured.layout.programHeaders[segment.programHeaderIndex];
    if (load.type != LoadProgramHeader ||
        dynamic->virtualAddress < load.virtualAddress ||
        dynamic->fileSize > segment.fileBytes.size() ||
        dynamic->virtualAddress - load.virtualAddress >
            segment.fileBytes.size() - dynamic->fileSize)
      continue;
    auto const offset = static_cast<std::size_t>(dynamic->virtualAddress -
                                                 load.virtualAddress);
    bool hasStringTable{};
    bool hasSymbolTable{};
    bool hasTerminator{};
    for (std::size_t cursor = 0;
         cursor + 16 <= static_cast<std::size_t>(dynamic->fileSize);
         cursor += 16) {
      auto const tag = ReadU64(segment.fileBytes, offset + cursor);
      auto const value = ReadU64(segment.fileBytes, offset + cursor + 8);
      if (tag == 0) {
        hasTerminator = true;
        break;
      }
      if (tag == 5 && value != 0) hasStringTable = true;
      if (tag == 6 && value != 0) hasSymbolTable = true;
    }
    return hasTerminator && hasStringTable && hasSymbolTable;
  }
  return false;
}
}  // namespace upx_killer::elf_host::debugging
