#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "Core/PE/Parsing/PeParser.h"

namespace upx_killer::engine::pe::imports::internal {
struct ImportRange {
  std::uint32_t begin{};
  std::uint32_t end{};

  [[nodiscard]] bool Overlaps(std::uint32_t rva, std::size_t size) const noexcept {
    return static_cast<std::uint64_t>(rva) < end && begin < static_cast<std::uint64_t>(rva) + size;
  }
};

struct SourceImportLayoutResult {
  bool complete{};
  std::vector<ImportRange> occupiedRanges;
};

// Identifies only source-file bytes proven to belong to the loader's import
// descriptors and thunk arrays. The packed Import Directory is not the UPX
// compressed-import stream used to restore the original image.
class SourceImportLayout final {
 public:
  [[nodiscard]] static SourceImportLayoutResult Analyze(std::span<std::byte const> sourceBytes,
                                                        PeImageLayout const& layout) noexcept;
};
}  // namespace upx_killer::engine::pe::imports::internal
