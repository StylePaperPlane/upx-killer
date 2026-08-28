#pragma once

#include "Core/PE/Rebasing/PeFileRebaser.h"

#include <cstddef>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::relocations
{
    struct LoadedImageSnapshot
    {
        LoadedAddress loadedBase;
        std::span<std::byte const> bytes;
    };

    struct RelocationSlot
    {
        RelativeVirtualAddress location;
        RelativeVirtualAddress imageTarget;
    };

    struct RelocationRebuildPlan
    {
        LoadedAddress preferredImageBase;
        std::vector<RelocationSlot> slots;
        std::vector<std::byte> directoryBytes;
    };

    enum class RelocationRebuildError
    {
        None,
        InvalidInput,
        EvidenceInsufficient,
        CandidatesAmbiguous,
        NoRelocations,
    };

    struct RelocationRebuildResult
    {
        std::optional<RelocationRebuildPlan> plan;
        RelocationRebuildError error{ RelocationRebuildError::None };

        [[nodiscard]] bool Succeeded() const noexcept { return plan.has_value(); }
    };

    class RelocationReconstructor final
    {
    public:
        [[nodiscard]] static RelocationRebuildResult Reconstruct(
            std::span<LoadedImageSnapshot const> snapshots,
            std::span<rebasing::SourceRelocationSlot const> sourceSlots,
            std::uint32_t sizeOfHeaders,
            std::uint32_t sizeOfImage,
            LoadedAddress preferredImageBase) noexcept;
    };
}
