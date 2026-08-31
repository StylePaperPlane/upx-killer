#pragma once

#include "Core/Targets/TargetDescriptor.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace upx_killer::application {
struct TemporaryArtifactAllocation {
  std::filesystem::path outputPath;
  bool retainFailedOutput{};
};

struct TemporaryArtifactAllocationResult {
  std::optional<TemporaryArtifactAllocation> allocation;
  std::string detailCode;
  std::uint32_t nativeCode{};
};

class ITemporaryArtifactWorkspace {
 public:
  virtual ~ITemporaryArtifactWorkspace() = default;
  [[nodiscard]] virtual TemporaryArtifactAllocationResult Allocate(
      std::filesystem::path const& targetPath,
      contracts::TargetDescriptor const& target) const noexcept = 0;
};
}
