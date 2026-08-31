#pragma once

#include "Core/PE/OepDiscovery/UpxOepLocator.h"

#include <cstddef>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::oep::internal {
class UpxTailTransferAnalyzer final {
 public:
  [[nodiscard]] static std::vector<OepTransferCandidate> Analyze(
      std::span<std::byte const> sourceBytes, PeImageLayout const& layout,
      PeSection const& stub, std::size_t rawStart, std::size_t rawEnd);
};
}
