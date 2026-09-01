#include "Application/PE/PeUnpackBackend.h"

#include "Application/PE/Translation/PeJobContractTranslator.h"

#include <utility>

namespace upx_killer::engine::application {
contracts::BackendManifest PeUnpackBackend::Manifest() const {
  return capabilities_.Manifest("pe.windows.upx");
}

contracts::BackendProbeResult PeUnpackBackend::Probe(
    contracts::UnpackJobRequest const& request) const noexcept {
  return probe_.Execute(request);
}

contracts::JobResult PeUnpackBackend::Execute(
    contracts::UnpackJobRequest const& request,
    contracts::ProgressCallback const& progress,
    std::stop_token stopToken) noexcept {
  auto translated = pe_translation::PeJobContractTranslator::Request(request);
  if (!translated.request) return std::move(translated.failure);
  auto engineRequest = std::move(*translated.request);
  auto engineProgress = [&](EngineStage stage) {
    if (progress)
      progress(pe_translation::PeJobContractTranslator::Progress(stage));
  };

  auto preparation = preparation_.Execute(engineRequest, engineProgress);
  if (!preparation.target)
    return pe_translation::PeJobContractTranslator::PreparationFailure(
        preparation);

  auto prepared = std::move(*preparation.target);
  auto capture = capture_.Execute(engineRequest, prepared, engineProgress,
                                  stopToken);
  if (!capture.evidence)
    return pe_translation::PeJobContractTranslator::CaptureFailure(capture);

  auto reconstruction = reconstruction_.Execute(
      engineRequest, prepared, *capture.evidence, engineProgress);
  if (!reconstruction.image)
    return pe_translation::PeJobContractTranslator::ReconstructionFailure(
        reconstruction);

  auto reconstructed = std::move(*reconstruction.image);
  auto fixed = std::move(reconstructed.image);
  auto publication = publication_.Execute(
      {engineRequest.outputPath, std::move(fixed.bytes),
       PeBackendCapabilities::Describe(prepared.layout),
       prepared.dependencyDirectory, 3000, fixed.quality,
       std::move(fixed.warnings), engineRequest.retainFailedOutput},
      engineProgress);
  return pe_translation::PeJobContractTranslator::Publication(
      std::move(publication));
}
}
