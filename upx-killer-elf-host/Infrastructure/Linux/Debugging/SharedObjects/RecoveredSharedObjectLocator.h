#pragma once

#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.h"

#include <filesystem>

namespace upx_killer::elf_host::debugging {

class RecoveredSharedObjectLocator final {
 public:
  [[nodiscard]] static std::optional<RecoveredElfImage> Find(
      pid_t pid, std::filesystem::path const& targetPath,
      engine::elf::ElfImageLayout const& recoveredLayout);
  [[nodiscard]] static bool AllSegmentsReadable(
      pid_t pid, RecoveredElfImage const& recovered);
};

}  // namespace upx_killer::elf_host::debugging
