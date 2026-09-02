#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <string>

namespace upx_killer::engine::elf::shared_objects {

struct SharedObjectNormalizationResult {
  bool normalized{};
  std::string detailCode;
};

class LoadedSharedObjectNormalizer final {
 public:
  [[nodiscard]] static SharedObjectNormalizationResult Normalize(
      CapturedElfImage& captured,
      ElfImageLayout const& packedLayout) noexcept;
};

}  // namespace upx_killer::engine::elf::shared_objects
