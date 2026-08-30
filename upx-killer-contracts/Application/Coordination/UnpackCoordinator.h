#pragma once

#include "Application/Backends/IUnpackBackend.h"

#include <memory>
#include <vector>

namespace upx_killer::contracts {
class UnpackCoordinator final {
 public:
  void Register(std::shared_ptr<IUnpackBackend> backend);

  [[nodiscard]] std::vector<BackendManifest> QueryCapabilities() const;
  [[nodiscard]] JobResult Execute(UnpackJobRequest const& request,
                                  ProgressCallback const& progress = {},
                                  std::stop_token stopToken = {}) const noexcept;

 private:
  std::vector<std::shared_ptr<IUnpackBackend>> backends_;
};
}
