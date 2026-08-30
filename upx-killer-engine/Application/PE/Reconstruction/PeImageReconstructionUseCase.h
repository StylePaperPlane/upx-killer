#pragma once

#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Core/PE/Fixing/PeImageFixer.h"

#include <functional>
#include <optional>

namespace upx_killer::engine::application::pe_reconstruction {
struct ReconstructedPeImage {
  pe::FixedPeImage image;
  pe::PeImageLayout layout;
};

struct PeImageReconstructionResult {
  std::optional<ReconstructedPeImage> image;
  EngineError error{EngineError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return image.has_value(); }
};

class PeImageReconstructionUseCase final {
 public:
  [[nodiscard]] PeImageReconstructionResult Execute(
      UnpackRequest const& request,
      pe_preparation::PreparedPeTarget const& target,
      pe_capture::PeCaptureEvidence const& evidence,
      std::function<void(EngineStage)> const& progress = {}) const noexcept;
};
}
