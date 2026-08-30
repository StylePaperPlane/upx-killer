#pragma once

#include "Application/Backends/IUnpackBackend.h"
#include "Core/PE/Parsing/PeParser.h"

#include <string>
#include <vector>

namespace upx_killer::engine::application {
class PeBackendCapabilities final {
 public:
  explicit PeBackendCapabilities(
      std::vector<contracts::TargetDescriptor> supportedTargets);

  [[nodiscard]] bool Supports(
      contracts::TargetDescriptor const& target) const noexcept;
  [[nodiscard]] bool Supports(pe::PeImageLayout const& layout) const noexcept;
  [[nodiscard]] contracts::BackendManifest Manifest(
      std::string backendId) const;
  [[nodiscard]] static contracts::TargetDescriptor Describe(
      pe::PeImageLayout const& layout) noexcept;

 private:
  std::vector<contracts::TargetDescriptor> supportedTargets_;
};
}
