#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <optional>
#include <string>

namespace upx_killer::engine::elf {

struct ElfRebuildResult {
  std::optional<std::vector<std::byte>> image;
  std::string detailCode;
};

class ElfImageRebuilder final {
 public:
  [[nodiscard]] static ElfRebuildResult Rebuild(
      CapturedElfImage const& captured,
      std::uint64_t maximumImageSize) noexcept;
};

}  // namespace upx_killer::engine::elf
