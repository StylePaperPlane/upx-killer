#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <array>
#include <cstddef>
#include <optional>

namespace upx_killer::engine::application {
struct TargetExecutionPlan {
  std::array<LoadedAddress, 3> captureBases{};
  std::size_t captureCount{};
  LoadedAddress outputBase;
  LoadedAddress validationBase;
  bool rebuildRelocations{};
  bool enableDynamicBase{};
  bool enableHighEntropyVa{};
};

class TargetExecutionPolicy final {
 public:
  [[nodiscard]] static std::optional<TargetExecutionPlan> Resolve(
      pe::PeImageLayout const& image) noexcept;
};
}
