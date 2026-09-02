#include "Application/Artifacts/ArtifactPublicationUseCase.h"

namespace upx_killer::engine::application::artifacts {
ArtifactPublicationResult ArtifactPublicationUseCase::Execute(
  ArtifactPublicationRequest request,
    contracts::ProgressCallback const& progress) const noexcept {
  try {
    if (progress)
      progress({contracts::JobStage::ValidatingArtifact,
                "artifact.progress.validating"});
    auto staged = store_.Stage(request.finalPath, request.bytes);
    if (!staged.temporaryPath) {
      return {std::nullopt, ArtifactPublicationError::StageFailed,
              staged.nativeError};
    }

    auto const validation = validator_.Validate(
        {*staged.temporaryPath, request.target, request.dependencyDirectory,
         request.validationTimeoutMilliseconds});
    auto const completed =
        request.target.imageKind == contracts::ImageKind::SharedLibrary
            ? validation.completed
            : (validation.completed || validation.timedOut);
    auto const valid = validation.loaderMappable && validation.exportsValid &&
                       completed &&
                       (!validation.completed || validation.exitCode == 0);
    if (!valid) {
      if (!request.retainFailedOutput) store_.Remove(*staged.temporaryPath);
      auto const nativeError =
          validation.completed && validation.exitCode != 0
              ? validation.exitCode
              : validation.nativeError;
      return {std::nullopt, ArtifactPublicationError::ValidationFailed,
              nativeError};
    }

    auto const promoteError =
        store_.Promote(*staged.temporaryPath, request.finalPath);
    if (promoteError != 0) {
      if (!request.retainFailedOutput) store_.Remove(*staged.temporaryPath);
      return {std::nullopt, ArtifactPublicationError::PromoteFailed,
              promoteError};
    }
    if (progress)
      progress({contracts::JobStage::Completed, "job.completed"});
    PublishedArtifact artifact{request.finalPath, request.quality, true,
                               std::move(request.warnings)};
    return {std::move(artifact), ArtifactPublicationError::None};
  } catch (...) {
    return {std::nullopt, ArtifactPublicationError::UnexpectedFailure};
  }
}
}
