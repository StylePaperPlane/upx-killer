#pragma once

#include "Core/ELF/Parsing/ElfParser.h"

#include <optional>
#include <span>

namespace upx_killer::engine::elf::oep {

struct ElfOepDiscoveryPlan {
  std::uint64_t packedEntryPoint{};
  bool hasUpxMarker{};
  bool hasStructuralEvidence{};
};

struct ElfOepDiscoveryResult {
  std::optional<ElfOepDiscoveryPlan> plan;
  std::string detailCode;
};

class UpxElfOepLocator final {
 public:
  [[nodiscard]] static ElfOepDiscoveryResult Analyze(
      std::span<std::byte const> source,
      ElfImageLayout const& layout) noexcept;
};

}  // namespace upx_killer::engine::elf::oep
