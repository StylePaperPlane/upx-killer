#pragma once

#include "Application/Backends/IUnpackBackend.h"

#include <functional>
#include <vector>

namespace upx_killer::application {
class IUnpackEngineClient {
 public:
  virtual ~IUnpackEngineClient() = default;
  using ProgressCallback = contracts::ProgressCallback;

  [[nodiscard]] virtual std::vector<contracts::BackendManifest> QueryCapabilities() noexcept = 0;
  [[nodiscard]] virtual contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      ProgressCallback const& progress = {}) noexcept = 0;
};
}
