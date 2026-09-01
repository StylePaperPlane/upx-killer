#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfLoadBiasResolver.h"

#include <algorithm>
#include <limits>

namespace {
constexpr std::uint32_t LoadProgramHeader = 1;
constexpr std::uint32_t WriteFlag = 2;
constexpr std::uint32_t ExecuteFlag = 1;

bool RangeCovered(
    std::span<upx_killer::elf_host::debugging::LinuxMemoryMapping const> mappings,
    std::uint64_t begin, std::uint64_t end,
    std::uint32_t flags) noexcept {
  auto cursor = begin;
  while (cursor < end) {
    auto const found = std::find_if(
        mappings.begin(), mappings.end(), [&](auto const& mapping) {
          return mapping.begin <= cursor && mapping.end > cursor;
        });
    if (found == mappings.end() || !found->read ||
        ((flags & ExecuteFlag) != 0 && !found->execute) ||
        ((flags & WriteFlag) == 0 && found->write))
      return false;
    cursor = std::min(end, found->end);
  }
  return true;
}
}  // namespace

namespace upx_killer::elf_host::debugging {
std::optional<std::uint64_t> RecoveredElfLoadBiasResolver::Resolve(
    engine::elf::ElfImageLayout const& layout,
    std::uint64_t headerAddress,
    std::span<LinuxMemoryMapping const> mappings) noexcept {
  std::optional<std::uint64_t> resolved;
  for (auto const& anchor : layout.programHeaders) {
    if (anchor.type != LoadProgramHeader || anchor.fileOffset != 0 ||
        anchor.fileSize < 16 || headerAddress < anchor.virtualAddress)
      continue;
    auto const candidate = headerAddress - anchor.virtualAddress;
    auto const allLoadsCovered = std::all_of(
        layout.programHeaders.begin(), layout.programHeaders.end(),
        [&](auto const& load) {
          if (load.type != LoadProgramHeader || load.fileSize == 0) return true;
          if (load.virtualAddress >
                  std::numeric_limits<std::uint64_t>::max() - candidate ||
              load.fileSize > std::numeric_limits<std::uint64_t>::max() -
                                  candidate - load.virtualAddress)
            return false;
          auto const begin = candidate + load.virtualAddress;
          return RangeCovered(mappings, begin, begin + load.fileSize,
                              load.flags);
        });
    if (!allLoadsCovered) continue;
    if (resolved && *resolved != candidate) return std::nullopt;
    resolved = candidate;
  }
  return resolved;
}
}  // namespace upx_killer::elf_host::debugging
