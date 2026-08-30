#pragma once

#include "Application/PE/Capabilities/PeBackendCapabilities.h"

#include <array>
#include <cstddef>
#include <optional>

namespace upx_killer::engine::application::pe_preparation {
struct PeExecutionPlan {
  std::array<LoadedAddress, 3> captureBases{};
  std::size_t captureCount{};
  LoadedAddress outputBase;
  LoadedAddress validationBase;
  bool rebuildRelocations{};
  bool enableDynamicBase{};
  bool enableHighEntropyVa{};
};

class PeExecutionPlanFactory final {
 public:
  [[nodiscard]] static std::optional<PeExecutionPlan> Create(
      pe::PeImageLayout const& image,
      PeBackendCapabilities const& capabilities) noexcept;
};
}
