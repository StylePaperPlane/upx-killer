#include "Application/ELF/ElfUnpackBackend.h"

#include "Application/ELF/Translation/ElfJobContractTranslator.h"

namespace upx_killer::engine::application {
contracts::BackendManifest ElfUnpackBackend::Manifest() const {
  return ElfBackendCapabilities::Manifest();
}

contracts::BackendProbeResult ElfUnpackBackend::Probe(
    contracts::UnpackJobRequest const& request) const noexcept {
  return probe_.Execute(request);
}

contracts::JobResult ElfUnpackBackend::Execute(
    contracts::UnpackJobRequest const& request,
    contracts::ProgressCallback const& progress,
    std::stop_token stopToken) noexcept {
  if (progress)
    progress({contracts::JobStage::ValidatingTarget,
              "elf.progress.validating"});
  auto prepared = preparation_.Execute(request);
  if (!prepared.target)
    return elf_translation::ElfJobContractTranslator::PreparationFailure(
        prepared);
  if (progress)
    progress({contracts::JobStage::DiscoveringEntryPoint,
              "elf.progress.discovering_entry"});
  auto captured = capture_.Execute(
      {*prepared.target, request.timeoutMilliseconds,
       request.maximumImageSize},
      stopToken);
  if (!captured.image)
    return elf_translation::ElfJobContractTranslator::CaptureFailure(captured);
  if (progress)
    progress({contracts::JobStage::RebuildingImage,
              "elf.progress.rebuilding_image"});
  auto reconstructed = reconstruction_.Execute(
      *captured.image, request.maximumImageSize);
  if (!reconstructed.bytes)
    return elf_translation::ElfJobContractTranslator::ReconstructionFailure(
        reconstructed);
  auto const descriptor =
      ElfBackendCapabilities::DescriptorFor(prepared.target->packedLayout);
  if (!descriptor)
    return {contracts::JobOutcome::Failed,
            contracts::ErrorCategory::Internal,
            "elf.capability.descriptor_missing", std::nullopt, 0};
  auto publication = publication_.Execute(
      {request.outputPath, std::move(*reconstructed.bytes), *descriptor,
       prepared.target->dependencyDirectory, request.timeoutMilliseconds,
       contracts::ArtifactQuality::Complete, {}, request.retainFailedOutput},
      progress);
  return elf_translation::ElfJobContractTranslator::Publication(
      std::move(publication));
}
}  // namespace upx_killer::engine::application
