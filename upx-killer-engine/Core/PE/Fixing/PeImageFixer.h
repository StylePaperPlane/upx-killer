#pragma once

#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/Fixing/ImagePlacementPlan.h"

#include <cstddef>
#include <optional>
#include <vector>

namespace upx_killer::engine::pe {
struct FixRequest {
  RelativeVirtualAddress oep;
  std::optional<ImportRebuildPlan> imports;
  fixing::ImagePlacementPlan imagePlacement;
};

struct FixedPeImage {
  std::vector<std::byte> bytes;
  ArtifactQuality quality{ArtifactQuality::Partial};
  std::vector<std::string> warnings;
};

struct FixResult {
  std::optional<FixedPeImage> image;
  EngineError error{EngineError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return image.has_value(); }
};

class PeImageFixer final {
 public:
  [[nodiscard]] static FixResult Rebuild(PeImageLayout const& layout,
                                         dumping::DumpedImage const& dump,
                                         FixRequest const& request) noexcept;
};
}
