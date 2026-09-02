#include "Core/ELF/OepDiscovery/UpxElfOepLocator.h"

#include <algorithm>
#include <array>

namespace upx_killer::engine::elf::oep {
ElfOepDiscoveryResult UpxElfOepLocator::Analyze(
    std::span<std::byte const> source,
    ElfImageLayout const& layout) noexcept {
  constexpr std::array<std::byte, 4> marker{
      std::byte{0x55}, std::byte{0x50}, std::byte{0x58}, std::byte{0x21}};
  auto const hasMarker = std::search(source.begin(), source.end(),
                                     marker.begin(), marker.end()) != source.end();

  std::size_t loadCount{};
  bool packedEntryInExecutableLoad{};
  bool sparseWritableLoad{};
  for (auto const& header : layout.programHeaders) {
    if (header.type != 1) continue;
    ++loadCount;
    if ((header.flags & 2) != 0 &&
        header.memorySize > header.fileSize + 0x1000)
      sparseWritableLoad = true;
    if ((header.flags & 1) != 0 && layout.entryPoint >= header.virtualAddress &&
        layout.entryPoint < header.virtualAddress + header.memorySize)
      packedEntryInExecutableLoad = true;
  }
  auto const structural = loadCount == 2 && packedEntryInExecutableLoad &&
                          sparseWritableLoad && source.size() >= 1024 &&
                          layout.sectionHeaderOffset == 0 &&
                          layout.sectionHeaderCount == 0;
  if (!hasMarker && !structural) return {{}, "elf.packer.unsupported"};
  return {ElfOepDiscoveryPlan{layout.entryPoint, hasMarker, structural}, {}};
}
}  // namespace upx_killer::engine::elf::oep
