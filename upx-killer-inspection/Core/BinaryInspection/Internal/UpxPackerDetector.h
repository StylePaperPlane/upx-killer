#pragma once

#include "Core/BinaryInspection/TargetBinaryInspector.h"

#include <cstddef>
#include <span>

namespace upx_killer::core::binary_inspection::internal {
enum class ContainerFormat {
  Pe,
  Elf,
};

struct UpxDetectionEvidence {
  ContainerFormat container{};
  bool canonicalLayout{};
  bool packedLayout{};
};

class UpxPackerDetector final {
 public:
  [[nodiscard]] static UpxPackerInformation Analyze(
      std::span<std::byte const> prefix,
      std::span<std::byte const> suffix,
      UpxDetectionEvidence const& evidence) noexcept;
};
}  // namespace upx_killer::core::binary_inspection::internal
