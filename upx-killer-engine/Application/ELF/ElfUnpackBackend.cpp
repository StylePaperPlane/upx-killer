#include "Application/ELF/ElfUnpackBackend.h"

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
  if (!prepared.target) return std::move(prepared.failure);
  if (progress)
    progress({contracts::JobStage::DiscoveringEntryPoint,
              "elf.progress.discovering_entry"});
  auto captured = capture_.Execute(
      {*prepared.target, request.timeoutMilliseconds,
       request.maximumImageSize},
      stopToken);
  if (!captured.image) return std::move(captured.failure);
  if (progress)
    progress({contracts::JobStage::RebuildingImage,
              "elf.progress.rebuilding_image"});
  auto reconstructed = reconstruction_.Execute(
      *captured.image, request.maximumImageSize);
  if (!reconstructed.bytes) return std::move(reconstructed.failure);
  auto const descriptor =
      ElfBackendCapabilities::DescriptorFor(prepared.target->packedLayout);
  if (!descriptor)
    return {contracts::JobOutcome::Failed,
            contracts::ErrorCategory::Internal,
            "elf.capability.descriptor_missing", std::nullopt, 0};
  return publisher_.Publish(
      {request.outputPath, *reconstructed.bytes,
       *descriptor,
       prepared.target->dependencyDirectory,
       request.timeoutMilliseconds, request.retainFailedOutput},
      progress);
}
}  // namespace upx_killer::engine::application
