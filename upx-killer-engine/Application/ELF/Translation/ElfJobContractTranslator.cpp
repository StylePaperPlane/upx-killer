#include "Application/ELF/Translation/ElfJobContractTranslator.h"

#include <utility>

namespace {
using namespace upx_killer;

contracts::JobResult Failure(contracts::JobOutcome outcome,
                             contracts::ErrorCategory category,
                             std::string detailCode,
                             std::uint32_t nativeCode = 0) {
  return {outcome, category, std::move(detailCode), std::nullopt, nativeCode};
}
}  // namespace

namespace upx_killer::engine::application::elf_translation {
contracts::JobResult ElfJobContractTranslator::PreparationFailure(
    elf_preparation::ElfPreparationResult const& result) noexcept {
  using elf_preparation::ElfPreparationError;
  switch (result.error) {
    case ElfPreparationError::SourceReadFailed:
    case ElfPreparationError::InvalidTarget:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Input, result.detailCode,
                     result.nativeCode);
    case ElfPreparationError::UnsupportedTarget:
    case ElfPreparationError::UnsupportedPacker:
      return Failure(contracts::JobOutcome::UnsupportedTarget,
                     contracts::ErrorCategory::UnsupportedTarget,
                     result.detailCode, result.nativeCode);
    case ElfPreparationError::InvalidEntryPoint:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::InvalidRequest,
                     result.detailCode, result.nativeCode);
    case ElfPreparationError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal, result.detailCode,
                     result.nativeCode);
    case ElfPreparationError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed,
                 contracts::ErrorCategory::Internal,
                 "elf.preparation.missing_failure");
}

contracts::JobResult ElfJobContractTranslator::CaptureFailure(
    elf_capture::ElfCaptureResult const& result) noexcept {
  using elf_capture::ElfCaptureError;
  switch (result.error) {
    case ElfCaptureError::InvalidRequest:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::InvalidRequest,
                     result.detailCode, result.nativeCode);
    case ElfCaptureError::ConfigurationFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Configuration,
                     result.detailCode, result.nativeCode);
    case ElfCaptureError::ExecutionFailed:
    case ElfCaptureError::EntryPointMismatch:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Execution, result.detailCode,
                     result.nativeCode);
    case ElfCaptureError::ReconstructionFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     result.detailCode, result.nativeCode);
    case ElfCaptureError::Cancelled:
      return Failure(contracts::JobOutcome::Cancelled,
                     contracts::ErrorCategory::Cancelled, result.detailCode,
                     result.nativeCode);
    case ElfCaptureError::TimedOut:
      return Failure(contracts::JobOutcome::TimedOut,
                     contracts::ErrorCategory::TimedOut, result.detailCode,
                     result.nativeCode);
    case ElfCaptureError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal, result.detailCode,
                     result.nativeCode);
    case ElfCaptureError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed,
                 contracts::ErrorCategory::Internal,
                 "elf.capture.missing_failure");
}

contracts::JobResult ElfJobContractTranslator::ReconstructionFailure(
    elf_reconstruction::ElfReconstructionResult const& result) noexcept {
  using elf_reconstruction::ElfReconstructionError;
  switch (result.error) {
    case ElfReconstructionError::RebuildFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     result.detailCode);
    case ElfReconstructionError::ValidationFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Validation,
                     result.detailCode);
    case ElfReconstructionError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal, result.detailCode);
    case ElfReconstructionError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed,
                 contracts::ErrorCategory::Internal,
                 "elf.reconstruction.missing_failure");
}

contracts::JobResult ElfJobContractTranslator::Publication(
    artifacts::ArtifactPublicationResult result) noexcept {
  if (result.artifact) {
    contracts::JobResult mapped{};
    mapped.outcome =
        result.artifact->quality == contracts::ArtifactQuality::Complete
            ? contracts::JobOutcome::Completed
            : contracts::JobOutcome::Partial;
    mapped.category = contracts::ErrorCategory::None;
    mapped.detailCode = "job.completed";
    mapped.artifact = contracts::JobArtifact{
        std::move(result.artifact->path), result.artifact->quality,
        result.artifact->loaderMappable,
        std::move(result.artifact->warnings)};
    return mapped;
  }
  using artifacts::ArtifactPublicationError;
  switch (result.error) {
    case ArtifactPublicationError::StageFailed:
    case ArtifactPublicationError::PromoteFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Storage,
                     "artifact.write_failed", result.nativeError);
    case ArtifactPublicationError::ValidationFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Validation,
                     "elf.artifact.validation_failed", result.nativeError);
    case ArtifactPublicationError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal,
                     "artifact.publication_failed", result.nativeError);
    case ArtifactPublicationError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed,
                 contracts::ErrorCategory::Internal,
                 "artifact.publication.missing_failure");
}
}  // namespace upx_killer::engine::application::elf_translation
