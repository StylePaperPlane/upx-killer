#include "Application/PE/PeUnpackBackend.h"

#include <utility>

namespace {
using namespace upx_killer;

engine::UnpackRequest ToEngineRequest(contracts::UnpackJobRequest const& request,
                                      bool& valid) {
  engine::UnpackRequest result{};
  result.targetPath = request.targetPath;
  result.outputPath = request.outputPath;
  result.timeoutMilliseconds = request.timeoutMilliseconds;
  result.maximumImageSize = request.maximumImageSize;
  result.retainFailedOutput = request.retainFailedOutput;
  valid = true;
  if (request.entryPoint) {
    if (request.entryPoint->kind !=
            contracts::EntryPointAddressKind::RelativeVirtualAddress ||
        request.entryPoint->value > UINT32_MAX) {
      valid = false;
    } else {
      result.oep = engine::RelativeVirtualAddress{
          static_cast<std::uint32_t>(request.entryPoint->value)};
    }
  }
  return result;
}

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

std::string DetailCode(engine::EngineError error) {
  using engine::EngineError;
  switch (error) {
    case EngineError::None: return {};
    case EngineError::InvalidPe: return "pe.target.invalid";
    case EngineError::UnsupportedPacker: return "pe.packer.unsupported";
    case EngineError::OepNotFound: return "pe.oep.not_found";
    case EngineError::ImportsNotFound: return "pe.imports.not_found";
    case EngineError::ImportsAmbiguous: return "pe.imports.ambiguous";
    case EngineError::SourceRelocationsInvalid: return "pe.relocations.source_invalid";
    case EngineError::RelocationEvidenceInsufficient:
      return "pe.relocations.evidence_insufficient";
    case EngineError::RelocationCandidatesAmbiguous:
      return "pe.relocations.candidates_ambiguous";
    case EngineError::RelocationValidationFailed:
    case EngineError::Pe32RelocationValidationFailed:
      return "pe.relocations.validation_failed";
    case EngineError::Wow64Unavailable: return "pe.wow64.unavailable";
    case EngineError::TargetMachineMismatch: return "pe.machine.mismatch";
    case EngineError::UnsupportedPe32RelocationType:
      return "pe.relocations.pe32_type_unsupported";
    case EngineError::DllLoaderUnavailable: return "pe.dll.loader_unavailable";
    case EngineError::LoadingTargetLibraryFailed: return "pe.dll.load_failed";
    case EngineError::TargetLibraryNotFound: return "pe.dll.target_not_found";
    case EngineError::TargetLibraryAttachInvalid: return "pe.dll.attach_invalid";
    case EngineError::ExportDirectoryInvalid: return "pe.exports.invalid";
    case EngineError::ExportValidationFailed: return "pe.exports.validation_failed";
    case EngineError::OutputWriteFailed: return "artifact.write_failed";
    case EngineError::OutputValidationFailed: return "artifact.validation_failed";
    case EngineError::Cancelled: return "job.cancelled";
    case EngineError::TimedOut: return "job.timed_out";
    default: return "pe.execution.failed";
  }
}

contracts::ErrorCategory Category(engine::EngineError error) noexcept {
  using engine::EngineError;
  switch (error) {
    case EngineError::None: return contracts::ErrorCategory::None;
    case EngineError::InvalidPe:
    case EngineError::OepOutOfRange: return contracts::ErrorCategory::Input;
    case EngineError::UnsupportedPe32:
    case EngineError::UnsupportedArchitecture:
    case EngineError::UnsupportedImageKind:
    case EngineError::UnsupportedPacker: return contracts::ErrorCategory::UnsupportedTarget;
    case EngineError::OutputWriteFailed: return contracts::ErrorCategory::Storage;
    case EngineError::OutputValidationFailed:
    case EngineError::RelocationValidationFailed:
    case EngineError::Pe32RelocationValidationFailed:
    case EngineError::ExportValidationFailed:
      return contracts::ErrorCategory::Validation;
    case EngineError::Cancelled: return contracts::ErrorCategory::Cancelled;
    case EngineError::TimedOut: return contracts::ErrorCategory::TimedOut;
    case EngineError::RebuildFailed:
    case EngineError::ImportsNotFound:
    case EngineError::ImportsAmbiguous:
    case EngineError::RelocationEvidenceInsufficient:
    case EngineError::RelocationCandidatesAmbiguous:
      return contracts::ErrorCategory::Reconstruction;
    default: return contracts::ErrorCategory::Execution;
  }
}

contracts::JobOutcome MapOutcome(engine::EngineOutcome outcome) noexcept {
  using engine::EngineOutcome;
  switch (outcome) {
    case EngineOutcome::Completed: return contracts::JobOutcome::Completed;
    case EngineOutcome::Partial: return contracts::JobOutcome::Partial;
    case EngineOutcome::UnsupportedTarget:
    case EngineOutcome::NeedsOep:
    case EngineOutcome::OepNotFound:
      return contracts::JobOutcome::UnsupportedTarget;
    case EngineOutcome::Cancelled: return contracts::JobOutcome::Cancelled;
    case EngineOutcome::TimedOut: return contracts::JobOutcome::TimedOut;
    case EngineOutcome::Failed: return contracts::JobOutcome::Failed;
  }
  return contracts::JobOutcome::Failed;
}

contracts::JobResult MapResult(engine::EngineResult result) {
  contracts::JobResult mapped{};
  mapped.outcome = MapOutcome(result.outcome);
  mapped.category = Category(result.error);
  mapped.detailCode = DetailCode(result.error);
  mapped.nativeCode = result.nativeError;
  if (result.artifact) {
    mapped.artifact = contracts::JobArtifact{
        std::move(result.artifact->path),
        result.artifact->quality == engine::ArtifactQuality::Complete
            ? contracts::ArtifactQuality::Complete
            : contracts::ArtifactQuality::Partial,
        result.artifact->loaderMappable,
        std::move(result.artifact->warnings)};
  }
  return mapped;
}
}

namespace upx_killer::engine::application {
contracts::BackendManifest PeUnpackBackend::Manifest() const {
  using namespace contracts;
  return {"pe.windows.upx",
          {{BinaryFamily::Pe, BinaryClass::Bits32, CpuArchitecture::X86,
            ImageKind::Executable},
           {BinaryFamily::Pe, BinaryClass::Bits64, CpuArchitecture::X64,
            ImageKind::Executable},
           {BinaryFamily::Pe, BinaryClass::Bits32, CpuArchitecture::X86,
            ImageKind::SharedLibrary}}};
}

contracts::BackendProbeResult PeUnpackBackend::Probe(
    contracts::UnpackJobRequest const& request) const noexcept {
  return probe_.Execute(request);
}

contracts::JobResult PeUnpackBackend::Execute(
    contracts::UnpackJobRequest const& request,
    contracts::ProgressCallback const& progress,
    std::stop_token stopToken) noexcept {
  bool valid{};
  auto engineRequest = ToEngineRequest(request, valid);
  if (!valid) {
    return {contracts::JobOutcome::Failed, contracts::ErrorCategory::InvalidRequest,
            "pe.entry_point.kind_unsupported"};
  }
  auto engineProgress = [&](EngineStage stage) {
    if (progress) progress({MapStage(stage), {}});
  };
  auto preparation = preparation_.Execute(engineRequest, engineProgress);
  if (!preparation.target)
    return MapResult({preparation.outcome, preparation.error, std::nullopt,
                      preparation.nativeError});
  auto prepared = std::move(*preparation.target);
  auto capture = capture_.Execute(engineRequest, prepared, engineProgress, stopToken);
  if (!capture.evidence)
    return MapResult({capture.outcome, capture.error, std::nullopt,
                      capture.nativeError});
  auto reconstruction = reconstruction_.Execute(
      engineRequest, prepared, *capture.evidence, engineProgress);
  if (!reconstruction.image)
    return MapResult({EngineOutcome::Failed, reconstruction.error});
  auto publication = publication_.Execute(
      engineRequest, prepared, std::move(*reconstruction.image), engineProgress);
  return MapResult({publication.outcome, publication.error,
                    std::move(publication.artifact), publication.nativeError});
}
}
