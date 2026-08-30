#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::rebasing {
struct SourceRelocationSlot {
  RelativeVirtualAddress location;
  std::optional<RelativeVirtualAddress> imageTarget;
};

struct RebasedFileImage {
  std::vector<std::byte> bytes;
  LoadedAddress requiredBase;
  std::vector<SourceRelocationSlot> sourceSlots;
};

enum class PeFileRebaseError {
  None,
  InvalidInput,
  MissingRelocations,
  InvalidRelocationDirectory,
  UnsupportedRelocationType,
};

struct PeFileRebaseResult {
  std::optional<RebasedFileImage> image;
  PeFileRebaseError error{PeFileRebaseError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return image.has_value(); }
};

class PeFileRebaser final {
 public:
  [[nodiscard]] static PeFileRebaseResult Rebase(std::span<std::byte const> source,
                                                 PeImageLayout const& layout,
                                                 LoadedAddress requiredBase) noexcept;
};
}
