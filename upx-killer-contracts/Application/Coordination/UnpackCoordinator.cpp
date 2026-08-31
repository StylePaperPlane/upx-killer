#include "Application/Coordination/UnpackCoordinator.h"

#include <utility>

namespace upx_killer::contracts {
void UnpackCoordinator::Register(std::shared_ptr<IUnpackBackend> backend) {
  if (backend) backends_.push_back(std::move(backend));
}

std::vector<BackendManifest> UnpackCoordinator::QueryCapabilities() const {
  std::vector<BackendManifest> manifests;
  manifests.reserve(backends_.size());
  for (auto const& backend : backends_) manifests.push_back(backend->Manifest());
  return manifests;
}

JobResult UnpackCoordinator::Execute(UnpackJobRequest const& request,
                                     ProgressCallback const& progress,
                                     std::stop_token stopToken) const noexcept {
  try {
    if (request.targetPath.empty() || request.outputPath.empty() ||
        request.timeoutMilliseconds == 0 || request.maximumImageSize == 0) {
      return {JobOutcome::Failed, ErrorCategory::InvalidRequest,
              "job.request.invalid", std::nullopt, 0};
    }

    std::shared_ptr<IUnpackBackend> selected;
    BackendProbeResult selectedProbe{};
    for (auto const& backend : backends_) {
      auto probe = backend->Probe(request);
      if (!probe.recognized) continue;
      if (selected) {
        return {JobOutcome::Failed, ErrorCategory::Configuration,
                "coordinator.backend.multiple_matches", std::nullopt, 0};
      }
      selected = backend;
      selectedProbe = std::move(probe);
    }

    if (!selected) {
      return {JobOutcome::UnsupportedTarget, ErrorCategory::UnsupportedTarget,
              "target.unrecognized", std::nullopt, 0};
    }
    if (!selectedProbe.supported) {
      return {JobOutcome::UnsupportedTarget, ErrorCategory::UnsupportedTarget,
              selectedProbe.detailCode.empty() ? "target.unsupported"
                                               : std::move(selectedProbe.detailCode),
              std::nullopt, 0};
    }
    return selected->Execute(request, progress, stopToken);
  } catch (...) {
    return {JobOutcome::Failed, ErrorCategory::Internal,
            "coordinator.unhandled_exception", std::nullopt, 0};
  }
}
}
