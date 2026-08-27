#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::oep
{
    constexpr std::size_t MaximumOepCandidates = 32;

    enum class OepDiscoveryError
    {
        None,
        UnsupportedPacker,
        OepNotFound,
    };

    struct OepTransferCandidate
    {
        RelativeVirtualAddress transfer;
        RelativeVirtualAddress target;
    };

    struct OepDiscoveryPlan
    {
        RelativeVirtualAddress packedEntryPoint;
        RelativeVirtualAddress stubStart;
        std::uint32_t stubSize{};
        std::vector<OepTransferCandidate> candidates;
    };

    struct OepDiscoveryResult
    {
        std::optional<OepDiscoveryPlan> plan;
        OepDiscoveryError error{ OepDiscoveryError::None };

        [[nodiscard]] bool Succeeded() const noexcept { return plan.has_value(); }
    };

    class UpxOepLocator final
    {
    public:
        [[nodiscard]] static OepDiscoveryResult Analyze(
            std::span<std::byte const> sourceBytes,
            PeImageLayout const& layout) noexcept;
    };
}
