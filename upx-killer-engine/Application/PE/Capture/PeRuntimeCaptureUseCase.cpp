#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"

#include "Core/PE/Rebasing/NoSourceRelocations/NoSourceRelocationsImagePreparer.h"

namespace upx_killer::engine::application::pe_capture {
PeRuntimeCaptureResult PeRuntimeCaptureUseCase::Execute(
    UnpackRequest const& request,
    pe_preparation::PreparedPeTarget const& target,
    std::function<void(EngineStage)> const& progress,
    std::stop_token stopToken) const noexcept {
  try {
    struct StagedImage {
      std::vector<std::byte> bytes;
      LoadedAddress requiredBase;
      std::vector<pe::rebasing::SourceRelocationSlot> sourceSlots;
    };

    std::vector<StagedImage> stagedImages;
    stagedImages.reserve(target.executionPlan.captureCount);
    for (std::size_t index = 0; index < target.executionPlan.captureCount; ++index) {
      auto const base = target.executionPlan.captureBases[index];
      if (!target.hasSourceRelocations) {
        auto staging = pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
            target.sourceBytes, target.layout, base);
        if (!staging.image) {
          return {std::nullopt, EngineOutcome::Failed,
                  EngineError::SourceRelocationsInvalid};
        }
        stagedImages.push_back({std::move(staging.image->bytes),
                                staging.image->requiredBase,
                                std::move(staging.image->stagingOnlySlots)});
      } else {
        auto staging = pe::rebasing::PeFileRebaser::Rebase(
            target.sourceBytes, target.layout, base);
        if (!staging.image) {
          auto const error =
              target.layout.format == pe::PeFormat::Pe32 &&
                      staging.error == pe::rebasing::PeFileRebaseError::UnsupportedRelocationType
                  ? EngineError::UnsupportedPe32RelocationType
                  : EngineError::SourceRelocationsInvalid;
          return {std::nullopt, EngineOutcome::Failed, error};
        }
        stagedImages.push_back({std::move(staging.image->bytes),
                                staging.image->requiredBase,
                                std::move(staging.image->sourceSlots)});
      }
    }

    PeCaptureEvidence evidence{};
    evidence.runs.reserve(stagedImages.size());
    if (target.hasSourceRelocations && progress)
      progress(EngineStage::CapturingRelocations);
    for (std::size_t index = 0; index < stagedImages.size(); ++index) {
      auto captured = snapshotCapture_.CaptureOne(
          {target.targetPath,
           target.dependencyDirectory,
           target.layout.format,
           target.layout.imageKind,
           target.entryPointTarget,
           &target.layout,
           stagedImages[index].bytes,
           stagedImages[index].requiredBase,
           std::chrono::milliseconds{request.timeoutMilliseconds},
           request.maximumImageSize,
           index == 0 && !request.imports.has_value()},
          progress, stopToken);
      if (!captured.capture) {
        return {std::nullopt, captured.outcome, captured.error,
                captured.nativeError};
      }
      if (!evidence.runs.empty() &&
          captured.capture->entryPoint.value != evidence.runs.front().entryPoint.value) {
        return {std::nullopt, EngineOutcome::Failed,
                EngineError::RelocationEvidenceInsufficient};
      }
      evidence.runs.push_back(std::move(*captured.capture));
    }
    if (!stagedImages.empty())
      evidence.sourceRelocationSlots = std::move(stagedImages.front().sourceSlots);
    return {std::move(evidence), EngineOutcome::Completed, EngineError::None};
  } catch (...) {
    return {std::nullopt, EngineOutcome::Failed, EngineError::DumpIncomplete};
  }
}
}
