#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <optional>
#include <span>

namespace upx_killer::engine::pe::metadata {
struct EmbeddedOriginalPeHeader {
  std::size_t metadataOffset{};
  std::uint32_t firstRva{};
  std::uint32_t imageSize{};
  std::uint32_t importDescriptors{};
  PeDataDirectory tlsDirectory{};
};

// Accepts only a unique embedded header that agrees with the captured OEP,
// architecture, first section and bounded original import directory.
[[nodiscard]] std::optional<EmbeddedOriginalPeHeader> FindEmbeddedOriginalPeHeader(
    std::span<std::byte const> dumped, PeImageLayout const& source,
    RelativeVirtualAddress recoveredEntryPoint) noexcept;
}
