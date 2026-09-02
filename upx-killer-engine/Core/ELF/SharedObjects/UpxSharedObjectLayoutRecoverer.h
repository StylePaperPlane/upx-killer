#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <optional>
#include <span>
#include <string>

namespace upx_killer::engine::elf::shared_objects {

struct SharedObjectLayoutRecoveryResult {
  std::optional<ElfImageLayout> layout;
  std::string detailCode;
};

class UpxSharedObjectLayoutRecoverer final {
 public:
  [[nodiscard]] static SharedObjectLayoutRecoveryResult Recover(
      std::span<std::byte const> packedBytes,
      ElfImageLayout const& packedLayout) noexcept;
};

}  // namespace upx_killer::engine::elf::shared_objects
