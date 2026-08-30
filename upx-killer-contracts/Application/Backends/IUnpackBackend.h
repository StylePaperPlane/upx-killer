#pragma once

#include "Core/Jobs/UnpackJob.h"
#include "Core/Targets/TargetDescriptor.h"

#include <functional>
#include <optional>
#include <stop_token>
#include <string>
#include <vector>

namespace upx_killer::contracts {
struct BackendManifest {
  std::string backendId;
  std::vector<TargetDescriptor> capabilities;
};

struct BackendProbeResult {
  bool recognized{};
  bool supported{};
  std::optional<TargetDescriptor> target;
  std::string detailCode;
};

using ProgressCallback = std::function<void(ProgressEvent const&)>;

class IUnpackBackend {
 public:
  virtual ~IUnpackBackend() = default;

  [[nodiscard]] virtual BackendManifest Manifest() const = 0;
  [[nodiscard]] virtual BackendProbeResult Probe(UnpackJobRequest const& request) const noexcept = 0;
  [[nodiscard]] virtual JobResult Execute(UnpackJobRequest const& request,
                                          ProgressCallback const& progress,
                                          std::stop_token stopToken) noexcept = 0;
};
}
