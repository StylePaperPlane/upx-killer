#include "Infrastructure/Windows/Composition/WindowsPeUnpackEngine.h"

#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"
#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"
#include "Infrastructure/Windows/Capture/WindowsPeSnapshotCapture.h"
#include "Infrastructure/Windows/Storage/WindowsArtifactStore.h"
#include "Infrastructure/Windows/Storage/WindowsTargetSourceReader.h"
#include "Infrastructure/Windows/Verification/WindowsPeImageValidator.h"

namespace upx_killer::engine::composition {
EngineResult WindowsPeUnpackEngine::Execute(
    UnpackRequest const& request, ProgressCallback const& progress,
    std::stop_token stopToken) noexcept {
  try {
    storage::WindowsTargetSourceReader sourceReader;
    application::pe_preparation::PeTargetPreparationUseCase preparation{sourceReader};
    auto preparedResult = preparation.Execute(request, progress);
    if (!preparedResult.target)
      return {preparedResult.outcome, preparedResult.error, std::nullopt,
              preparedResult.nativeError};

    capture::WindowsPeSnapshotCapture snapshotCapture;
    application::pe_capture::PeRuntimeCaptureUseCase capture{snapshotCapture};
    auto captureResult = capture.Execute(
        request, *preparedResult.target, progress, stopToken);
    if (!captureResult.evidence)
      return {captureResult.outcome, captureResult.error, std::nullopt,
              captureResult.nativeError};

    application::pe_reconstruction::PeImageReconstructionUseCase reconstruction;
    auto reconstructed = reconstruction.Execute(
        request, *preparedResult.target, *captureResult.evidence, progress);
    if (!reconstructed.image)
      return {EngineOutcome::Failed, reconstructed.error};

    storage::WindowsArtifactStore artifactStore;
    verification::WindowsPeImageValidator imageValidator;
    application::artifacts::ArtifactPublicationUseCase publication{
        artifactStore, imageValidator};
    auto published = publication.Execute(
        request, *preparedResult.target, std::move(*reconstructed.image), progress);
    return {published.outcome, published.error, std::move(published.artifact),
            published.nativeError};
  } catch (...) {
    return {EngineOutcome::Failed, EngineError::RebuildFailed};
  }
}
}
