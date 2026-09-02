#include "Application/PE/Translation/PeJobContractTranslator.h"

#include <limits>
#include <utility>

namespace {
using namespace upx_killer;

contracts::JobStage MapStage(engine::EngineStage stage) noexcept {
  using engine::EngineStage;
  switch (stage) {
    case EngineStage::Validating:
      return contracts::JobStage::ValidatingTarget;
    case EngineStage::DiscoveringOep:
    case EngineStage::WaitingForOep:
      return contracts::JobStage::DiscoveringEntryPoint;
    case EngineStage::LoadingTargetLibrary:
    case EngineStage::Launching:
      return contracts::JobStage::LoadingTarget;
    case EngineStage::Dumping:
      return contracts::JobStage::CapturingImage;
    case EngineStage::RebuildingImports:
      return contracts::JobStage::RebuildingImports;
    case EngineStage::CapturingRelocations:
    case EngineStage::RebuildingRelocations:
      return contracts::JobStage::CapturingRelocations;
    case EngineStage::Fixing:
      return contracts::JobStage::RebuildingImage;
    case EngineStage::ValidatingOutput:
      return contracts::JobStage::ValidatingArtifact;
    case EngineStage::Completed:
      return contracts::JobStage::Completed;
  }
  return contracts::JobStage::ValidatingTarget;
}

contracts::JobResult Failure(contracts::JobOutcome outcome,
                             contracts::ErrorCategory category,
                             std::string detailCode,
                             std::uint32_t nativeCode = 0) {
  return {outcome, category, std::move(detailCode), std::nullopt, nativeCode};
}
}

namespace upx_killer::engine::application::pe_translation {
PeRequestTranslationResult PeJobContractTranslator::Request(
    contracts::UnpackJobRequest const& source) noexcept {
  try {
    UnpackRequest translated{};
    translated.targetPath = source.targetPath;
    translated.outputPath = source.outputPath;
    translated.timeoutMilliseconds = source.timeoutMilliseconds;
    translated.maximumImageSize = source.maximumImageSize;
    translated.retainFailedOutput = source.retainFailedOutput;
    if (source.entryPoint) {
      if (source.entryPoint->kind !=
              contracts::EntryPointAddressKind::RelativeVirtualAddress ||
          source.entryPoint->value >
              std::numeric_limits<std::uint32_t>::max())
        return {std::nullopt,
                {contracts::JobOutcome::Failed,
                 contracts::ErrorCategory::InvalidRequest,
                 "pe.entry_point.kind_unsupported"}};
      translated.oep = RelativeVirtualAddress{
          static_cast<std::uint32_t>(source.entryPoint->value)};
    }
    return {std::move(translated), {}};
  } catch (...) {
    return {std::nullopt,
            {contracts::JobOutcome::Failed,
             contracts::ErrorCategory::Internal,
             "pe.request.translation_failed"}};
  }
}

contracts::ProgressEvent PeJobContractTranslator::Progress(
    EngineStage stage) noexcept {
  return {MapStage(stage), {}};
}

contracts::JobResult PeJobContractTranslator::PreparationFailure(
    pe_preparation::PePreparationResult const& result) noexcept {
  using pe_preparation::PePreparationError;
  switch (result.error) {
    case PePreparationError::UnsupportedPe32:
    case PePreparationError::UnsupportedArchitecture:
    case PePreparationError::UnsupportedImageKind:
      return Failure(contracts::JobOutcome::UnsupportedTarget,
                     contracts::ErrorCategory::UnsupportedTarget,
                     "pe.target.unsupported", result.nativeError);
    case PePreparationError::UnsupportedPacker:
      return Failure(contracts::JobOutcome::UnsupportedTarget,
                     contracts::ErrorCategory::UnsupportedTarget,
                     "pe.packer.unsupported", result.nativeError);
    case PePreparationError::EntryPointNotFound:
      return Failure(contracts::JobOutcome::UnsupportedTarget,
                     contracts::ErrorCategory::Execution,
                     "pe.oep.not_found", result.nativeError);
    case PePreparationError::SourceReadFailed:
    case PePreparationError::InvalidPe:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Input,
                     "pe.target.invalid", result.nativeError);
    case PePreparationError::EntryPointOutOfRange:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Input,
                     "pe.entry_point.out_of_range", result.nativeError);
    case PePreparationError::SourceRelocationsInvalid:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Execution,
                     "pe.relocations.source_invalid", result.nativeError);
    case PePreparationError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal,
                     "pe.preparation.failed", result.nativeError);
    case PePreparationError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed, contracts::ErrorCategory::Internal,
                 "pe.preparation.missing_failure");
}

contracts::JobResult PeJobContractTranslator::CaptureFailure(
    pe_capture::PeRuntimeCaptureResult const& result) noexcept {
  using pe_capture::PeCaptureError;
  using pe_capture::PeSnapshotCaptureError;
  if (result.error == PeCaptureError::SnapshotFailed) {
    switch (result.snapshotError) {
      case PeSnapshotCaptureError::Cancelled:
        return Failure(contracts::JobOutcome::Cancelled,
                       contracts::ErrorCategory::Cancelled,
                       "job.cancelled", result.nativeError);
      case PeSnapshotCaptureError::TimedOut:
        return Failure(contracts::JobOutcome::TimedOut,
                       contracts::ErrorCategory::TimedOut,
                       "job.timed_out", result.nativeError);
      case PeSnapshotCaptureError::EntryPointNotFound:
        return Failure(contracts::JobOutcome::UnsupportedTarget,
                       contracts::ErrorCategory::Execution,
                       "pe.oep.not_found", result.nativeError);
      case PeSnapshotCaptureError::DllLoaderUnavailable:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Configuration,
                       "pe.dll.loader_unavailable", result.nativeError);
      case PeSnapshotCaptureError::TargetLibraryLaunchFailed:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "pe.dll.load_failed", result.nativeError);
      case PeSnapshotCaptureError::MachineMismatch:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "pe.machine.mismatch", result.nativeError);
      case PeSnapshotCaptureError::Wow64Unavailable:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Configuration,
                       "pe.wow64.unavailable", result.nativeError);
      case PeSnapshotCaptureError::TargetLibraryAttachInvalid:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "pe.dll.attach_invalid", result.nativeError);
      case PeSnapshotCaptureError::ControlledBaseUnavailable:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "pe.relocations.controlled_base_unavailable", result.nativeError);
      case PeSnapshotCaptureError::InvalidRequest:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Input,
                       "pe.capture.invalid_request", result.nativeError);
      case PeSnapshotCaptureError::None: break;
      default:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "pe.capture.failed", result.nativeError);
    }
  }
  switch (result.error) {
    case PeCaptureError::SourceRelocationsInvalid:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Execution,
                     "pe.relocations.source_invalid", result.nativeError);
    case PeCaptureError::UnsupportedPe32RelocationType:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::UnsupportedTarget,
                     "pe.relocations.pe32_type_unsupported", result.nativeError);
    case PeCaptureError::EntryPointsDiffer:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     "pe.relocations.evidence_insufficient", result.nativeError);
    case PeCaptureError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal,
                     "pe.capture.failed", result.nativeError);
    case PeCaptureError::SnapshotFailed:
    case PeCaptureError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed, contracts::ErrorCategory::Internal,
                 "pe.capture.missing_failure");
}

contracts::JobResult PeJobContractTranslator::ReconstructionFailure(
    pe_reconstruction::PeImageReconstructionResult const& result) noexcept {
  using pe_reconstruction::PeReconstructionError;
  switch (result.error) {
    case PeReconstructionError::ImportsNotFound:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     "pe.imports.not_found");
    case PeReconstructionError::ImportsAmbiguous:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     "pe.imports.ambiguous");
    case PeReconstructionError::RelocationEvidenceInsufficient:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     "pe.relocations.evidence_insufficient");
    case PeReconstructionError::RelocationCandidatesAmbiguous:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     "pe.relocations.candidates_ambiguous");
    case PeReconstructionError::RelocationValidationFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Validation,
                     "pe.relocations.validation_failed");
    case PeReconstructionError::OutputValidationFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Validation,
                     "artifact.validation_failed");
    case PeReconstructionError::FixingFailed:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Reconstruction,
                     result.fixError == pe::PeFixError::ExportDirectoryInvalid
                         ? "pe.exports.invalid"
                         : "pe.rebuild.failed");
    case PeReconstructionError::MissingCapture:
    case PeReconstructionError::UnexpectedFailure:
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Internal,
                     "pe.rebuild.failed");
    case PeReconstructionError::None: break;
  }
  return Failure(contracts::JobOutcome::Failed, contracts::ErrorCategory::Internal,
                 "pe.reconstruction.missing_failure");
}

contracts::JobResult PeJobContractTranslator::Publication(
    artifacts::ArtifactPublicationResult result) noexcept {
  try {
    if (result.artifact) {
      contracts::JobResult mapped{};
      mapped.outcome = result.artifact->quality == contracts::ArtifactQuality::Complete
                           ? contracts::JobOutcome::Completed
                           : contracts::JobOutcome::Partial;
      mapped.category = contracts::ErrorCategory::None;
      mapped.artifact = contracts::JobArtifact{
          std::move(result.artifact->path),
          result.artifact->quality,
          result.artifact->loaderMappable,
          std::move(result.artifact->warnings)};
      return mapped;
    }
    switch (result.error) {
      case artifacts::ArtifactPublicationError::StageFailed:
      case artifacts::ArtifactPublicationError::PromoteFailed:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Storage,
                       "artifact.write_failed", result.nativeError);
      case artifacts::ArtifactPublicationError::ValidationFailed:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Validation,
                       "artifact.validation_failed", result.nativeError);
      case artifacts::ArtifactPublicationError::UnexpectedFailure:
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Internal,
                       "artifact.publication_failed", result.nativeError);
      case artifacts::ArtifactPublicationError::None: break;
    }
    return Failure(contracts::JobOutcome::Failed,
                   contracts::ErrorCategory::Internal,
                   "artifact.publication.missing_failure");
  } catch (...) {
    return {contracts::JobOutcome::Failed,
            contracts::ErrorCategory::Internal,
            "pe.result.translation_failed"};
  }
}
}
