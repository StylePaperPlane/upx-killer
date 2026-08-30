#include "pch.h"
#include "Application/Unpacking/UnpackWorkflow.h"

namespace upx_killer::application {
UnpackWorkflow::UnpackWorkflow(std::shared_ptr<IUnpackEngineClient> client)
    : m_client(std::move(client)) {}

bool UnpackWorkflow::RefreshCapabilities() noexcept {
  auto manifests = m_client ? m_client->QueryCapabilities()
                            : std::vector<contracts::BackendManifest>{};
  std::scoped_lock lock{m_capabilitiesMutex};
  m_manifests = std::move(manifests);
  m_capabilitiesLoaded = true;
  return !m_manifests.empty();
}

bool UnpackWorkflow::CapabilitiesLoaded() const noexcept {
  std::scoped_lock lock{m_capabilitiesMutex};
  return m_capabilitiesLoaded;
}

bool UnpackWorkflow::HasCapabilities() const noexcept {
  std::scoped_lock lock{m_capabilitiesMutex};
  return !m_manifests.empty();
}

bool UnpackWorkflow::Supports(contracts::TargetDescriptor const& target) const noexcept {
  std::scoped_lock lock{m_capabilitiesMutex};
  for (auto const& manifest : m_manifests)
    for (auto const& capability : manifest.capabilities)
      if (capability == target) return true;
  return false;
}

UnpackResult UnpackWorkflow::Start(
    std::filesystem::path const& targetPath,
    std::optional<contracts::EntryPointHint> entryPoint,
    IUnpackEngineClient::ProgressCallback const& progress) const noexcept {
  if (!m_client) return {UnpackOutcome::Failed, {}, {}};

  contracts::UnpackJobRequest request{};
  request.targetPath = targetPath;
  request.entryPoint = entryPoint;
  auto result = m_client->Execute(request, progress);
  if (result.outcome == contracts::JobOutcome::Partial && result.artifact)
    return {UnpackOutcome::Partial, result.artifact->path, result.artifact->warnings};
  if (result.outcome == contracts::JobOutcome::Completed && result.artifact)
    return {UnpackOutcome::Succeeded, result.artifact->path, result.artifact->warnings};
  if (result.detailCode == "pe.oep.required") return {UnpackOutcome::NeedsOep, {}, {}};
  if (result.detailCode == "pe.packer.unsupported")
    return {UnpackOutcome::UnsupportedPacker, {}, {}};
  if (result.detailCode == "pe.oep.not_found") return {UnpackOutcome::OepNotFound, {}, {}};
  if (result.detailCode == "pe.imports.not_found")
    return {UnpackOutcome::ImportsNotFound, {}, {}};
  if (result.detailCode == "pe.imports.ambiguous")
    return {UnpackOutcome::ImportsAmbiguous, {}, {}};
  if (result.detailCode == "pe.relocations.evidence_insufficient" ||
      result.detailCode == "pe.relocations.candidates_ambiguous")
    return {UnpackOutcome::RelocationEvidenceFailed, {}, {}};
  if (result.detailCode == "pe.relocations.validation_failed" ||
      result.detailCode == "pe.relocations.source_invalid")
    return {UnpackOutcome::RelocationValidationFailed, {}, {}};
  if (result.detailCode == "pe.wow64.unavailable" ||
      result.detailCode == "pe.machine.mismatch")
    return {UnpackOutcome::Wow64Unavailable, {}, {}};
  if (result.detailCode == "pe.relocations.pe32_type_unsupported")
    return {UnpackOutcome::UnsupportedPe32Relocation, {}, {}};
  if (result.outcome == contracts::JobOutcome::UnsupportedTarget)
    return {UnpackOutcome::Unsupported, {}, {}};
  return {UnpackOutcome::Failed, {}, {}};
}
}
