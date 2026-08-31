#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <sys/types.h>

#include <cstdint>
#include <optional>

namespace upx_killer::elf_host::debugging {

struct RecoveredElfImage {
  engine::elf::ElfImageLayout layout;
  std::uint64_t headerAddress{};
  std::uint64_t loadBias{};
};

class RecoveredElfImageLocator final {
 public:
  [[nodiscard]] static std::optional<RecoveredElfImage> Find(
      pid_t pid, engine::elf::ElfImageLayout const& packed);
  [[nodiscard]] static bool AllSegmentsReady(
      pid_t pid, RecoveredElfImage const& recovered);
  [[nodiscard]] static std::optional<engine::elf::CapturedElfImage> Capture(
      pid_t pid, RecoveredElfImage const& recovered,
      std::uint64_t maximumSize);
  [[nodiscard]] static bool HasCompleteDynamicLinkage(
      engine::elf::CapturedElfImage const& captured) noexcept;
};

}  // namespace upx_killer::elf_host::debugging
