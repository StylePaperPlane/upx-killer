#pragma once

#include "Core/Images/CapturedImage.h"
#include "Core/PE/Fixing/ImagePlacementPlan.h"

#include <cstddef>
#include <optional>
#include <vector>

namespace upx_killer::engine::pe {
enum class PeFixError {
  None,
  EntryPointOutOfRange,
  ImagePlacementInvalid,
  RelocationSlotInvalid,
  ExportDirectoryInvalid,
  SectionLayoutInvalid,
  ImportPlanInvalid,
  HeaderWriteFailed,
  UnexpectedFailure,
};

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
  PeFixError error{PeFixError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return image.has_value(); }
};

class PeImageFixer final {
 public:
  [[nodiscard]] static FixResult Rebuild(PeImageLayout const& layout,
                                         images::CapturedImage const& capturedImage,
                                         FixRequest const& request) noexcept;
};
}
