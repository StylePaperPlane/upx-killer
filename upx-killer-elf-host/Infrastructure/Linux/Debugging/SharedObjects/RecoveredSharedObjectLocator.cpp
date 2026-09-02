#include "Infrastructure/Linux/Debugging/SharedObjects/RecoveredSharedObjectLocator.h"

#include "Infrastructure/Linux/Debugging/Memory/LinuxProcessMemory.h"

#include <algorithm>

namespace upx_killer::elf_host::debugging {
std::optional<RecoveredElfImage> RecoveredSharedObjectLocator::Find(
    pid_t pid, std::filesystem::path const& targetPath,
    engine::elf::ElfImageLayout const& recoveredLayout) {
  auto const expectedPath = std::filesystem::weakly_canonical(targetPath).string();
  auto const mappings = LinuxProcessMemory::ReadMappings(pid);
  for (auto const& mapping : mappings) {
    if (!mapping.read || mapping.offset != 0 ||
        mapping.path != expectedPath || mapping.end <= mapping.begin)
      continue;
    return RecoveredElfImage{recoveredLayout, mapping.begin, mapping.begin};
  }
  return std::nullopt;
}

bool RecoveredSharedObjectLocator::AllSegmentsReadable(
    pid_t pid, RecoveredElfImage const& recovered) {
  auto const mappings = LinuxProcessMemory::ReadMappings(pid);
  for (auto const& header : recovered.layout.programHeaders) {
    if (header.type != 1 || header.fileSize == 0) continue;
    auto cursor = recovered.loadBias + header.virtualAddress;
    auto const end = cursor + header.fileSize;
    if (end < cursor) return false;
    while (cursor < end) {
      auto const found = std::find_if(
          mappings.begin(), mappings.end(), [&](auto const& mapping) {
            return mapping.read && mapping.begin <= cursor &&
                   mapping.end > cursor;
          });
      if (found == mappings.end()) return false;
      cursor = std::min(end, found->end);
    }
  }
  return true;
}
}  // namespace upx_killer::elf_host::debugging
