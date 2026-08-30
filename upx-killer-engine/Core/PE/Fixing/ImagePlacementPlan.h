#pragma once

#include "Core/PE/Relocations/RelocationReconstructor.h"

#include <variant>

namespace upx_killer::engine::pe::fixing {
struct FixedImagePlacement {
  LoadedAddress preferredImageBase;
};

using ImagePlacementPlan =
    std::variant<FixedImagePlacement, relocations::RelocationRebuildPlan>;
}
