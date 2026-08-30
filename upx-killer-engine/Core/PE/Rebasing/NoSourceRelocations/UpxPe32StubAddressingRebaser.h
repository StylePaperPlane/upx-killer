#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <optional>
#include <span>

namespace upx_killer::engine::pe::rebasing::detail {
enum class UpxPe32StubAddressingRebaseStatus {
  NotApplicable,
  Applied,
  Invalid,
};

struct UpxPe32StubAddressingRebaseResult {
  UpxPe32StubAddressingRebaseStatus status{UpxPe32StubAddressingRebaseStatus::NotApplicable};
  std::optional<RelativeVirtualAddress> patchedLocation;
  std::optional<RelativeVirtualAddress> imageTarget;
};

class UpxPe32StubAddressingRebaser final {
 public:
  // Rewrites the single absolute compressed-source immediate used by the
  // canonical UPX x86 entry prologue. All opcode, section, address and sparse
  // destination invariants must match before any byte is changed.
  [[nodiscard]] static UpxPe32StubAddressingRebaseResult Rebase(
      std::span<std::byte> stagedImage, PeImageLayout const& layout,
      LoadedAddress requiredBase) noexcept;
};
}
