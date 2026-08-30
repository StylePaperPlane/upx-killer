#pragma once

#include "Core/PE/Parsing/PeParser.h"
#include "Core/Dumping/ProcessImageDumper.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::sections {
struct SectionLayoutInput {
  std::span<std::byte const> loadedImage;
  LoadedAddress loadedBase;
  RelativeVirtualAddress oep;
  ImportRebuildPlan const* imports{};
  std::span<RelativeVirtualAddress const> exportCodeTargets;
  std::span<dumping::DumpedMemoryRegion const> memoryRegions;
};

struct RebuiltSection {
  std::array<char, 8> name{};
  RelativeVirtualAddress virtualAddress;
  std::uint32_t virtualSize{};
  std::uint32_t characteristics{};
};

struct SectionLayoutPlan {
  std::vector<RebuiltSection> sections;
  std::optional<PeDataDirectory> tlsDirectory;
};

enum class SectionLayoutError {
  None,
  InvalidInput,
  TooManySections,
};

struct SectionLayoutResult {
  std::optional<SectionLayoutPlan> plan;
  SectionLayoutError error{SectionLayoutError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return plan.has_value(); }
};

class SectionLayoutRebuilder final {
 public:
  [[nodiscard]] static SectionLayoutResult Build(PeImageLayout const& source,
                                                 SectionLayoutInput const& input) noexcept;
};
}
