#include "Application/ELF/Hosting/RemoteElfUnpackBackend.h"

#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"

namespace upx_killer::engine::application {
contracts::BackendManifest RemoteElfUnpackBackend::Manifest() const {
  return ElfBackendCapabilities::Manifest();
}

contracts::BackendProbeResult RemoteElfUnpackBackend::Probe(
    contracts::UnpackJobRequest const& request) const noexcept {
  return probe_.Execute(request);
}

contracts::JobResult RemoteElfUnpackBackend::Execute(
    contracts::UnpackJobRequest const& request,
    contracts::ProgressCallback const& progress,
    std::stop_token stopToken) noexcept {
  return client_.Execute(request, progress, stopToken);
}
}  // namespace upx_killer::engine::application
