#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <optional>
#include <span>

namespace upx_killer::engine::pe::validation {
enum class RebuiltPeImageValidationError {
  None,
  InvalidImage,
  InvalidImports,
  InvalidFixedPlacement,
  InvalidRelocations,
};

struct RebuiltPeImageValidationRequest {
  std::span<std::byte const> image;
  PeImageLayout const& sourceLayout;
  LoadedAddress outputBase;
  LoadedAddress relocationValidationBase;
  bool hasSourceRelocations{};
  std::optional<std::size_t> expectedRelocationCount;
};

struct RebuiltPeImageValidationResult {
  std::optional<PeImageLayout> layout;
  RebuiltPeImageValidationError error{RebuiltPeImageValidationError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return layout.has_value(); }
};

class RebuiltPeImageValidator final {
 public:
  [[nodiscard]] static RebuiltPeImageValidationResult Validate(
      RebuiltPeImageValidationRequest const& request) noexcept;
};
}
