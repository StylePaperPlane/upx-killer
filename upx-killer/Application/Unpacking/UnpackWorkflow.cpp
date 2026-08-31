#include "pch.h"
#include "Application/Unpacking/UnpackWorkflow.h"

namespace upx_killer::application {
UnpackWorkflow::UnpackWorkflow(
    std::shared_ptr<IUnpackEngineClient> client,
    std::shared_ptr<ITemporaryArtifactWorkspace> workspace)
    : m_client(std::move(client)), m_workspace(std::move(workspace)) {}

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

contracts::JobResult UnpackWorkflow::Start(
    std::filesystem::path const& targetPath,
    contracts::TargetDescriptor const& target,
    std::optional<contracts::EntryPointHint> entryPoint,
    IUnpackEngineClient::ProgressCallback const& progress) const noexcept {
  if (!m_client || !m_workspace) {
    return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Configuration,
            "workspace.unavailable"};
  }

  auto allocation = m_workspace->Allocate(targetPath, target);
  if (!allocation.allocation) {
    return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Storage,
            std::move(allocation.detailCode), std::nullopt,
            allocation.nativeCode};
  }

  contracts::UnpackJobRequest request{};
  request.targetPath = targetPath;
  request.outputPath = allocation.allocation->outputPath;
  request.retainFailedOutput = allocation.allocation->retainFailedOutput;
  request.entryPoint = entryPoint;
  return m_client->Execute(request, progress);
}
}
