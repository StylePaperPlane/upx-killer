#pragma once

#include "Application/Backends/IUnpackBackend.h"

namespace upx_killer::engine::application::elf_hosting {

class IElfHostClient {
 public:
  virtual ~IElfHostClient() = default;
  [[nodiscard]] virtual contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      contracts::ProgressCallback const& progress,
      std::stop_token stopToken) const noexcept = 0;
};

}  // namespace upx_killer::engine::application::elf_hosting
