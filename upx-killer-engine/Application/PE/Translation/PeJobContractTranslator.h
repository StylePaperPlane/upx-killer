#pragma once

#include "Application/Backends/IUnpackBackend.h"
#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"
#include "Core/Unpacking/UnpackTypes.h"

#include <optional>

namespace upx_killer::engine::application::pe_translation {
struct PeRequestTranslationResult {
  std::optional<UnpackRequest> request;
  contracts::JobResult failure;

  [[nodiscard]] bool Succeeded() const noexcept { return request.has_value(); }
};

class PeJobContractTranslator final {
 public:
  [[nodiscard]] static PeRequestTranslationResult Request(
      contracts::UnpackJobRequest const& request) noexcept;
  [[nodiscard]] static contracts::ProgressEvent Progress(
      EngineStage stage) noexcept;
  [[nodiscard]] static contracts::JobResult PreparationFailure(
      pe_preparation::PePreparationResult const& result) noexcept;
  [[nodiscard]] static contracts::JobResult CaptureFailure(
      pe_capture::PeRuntimeCaptureResult const& result) noexcept;
  [[nodiscard]] static contracts::JobResult ReconstructionFailure(
      pe_reconstruction::PeImageReconstructionResult const& result) noexcept;
  [[nodiscard]] static contracts::JobResult Publication(
      artifacts::ArtifactPublicationResult result) noexcept;
};
}
