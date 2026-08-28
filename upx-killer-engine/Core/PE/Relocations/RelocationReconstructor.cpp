#include "Core/PE/Relocations/RelocationReconstructor.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;

    std::uint64_t ReadU64(std::span<std::byte const> bytes, std::uint32_t offset) noexcept
    {
        std::uint64_t value{};
        std::memcpy(&value, bytes.data() + offset, sizeof(value));
        return value;
    }

    template <typename T>
    void Append(std::vector<std::byte>& bytes, T const& value)
    {
        auto const* begin = reinterpret_cast<std::byte const*>(&value);
        bytes.insert(bytes.end(), begin, begin + sizeof(value));
    }

    bool IsPackedResidue(
        std::span<rebasing::SourceRelocationSlot const> sourceSlots,
        RelativeVirtualAddress location,
        RelativeVirtualAddress target) noexcept
    {
        auto const found = std::find_if(
            sourceSlots.begin(), sourceSlots.end(),
            [&](rebasing::SourceRelocationSlot const& source)
            {
                return source.location.value == location.value;
            });
        return found != sourceSlots.end() && found->imageTarget &&
            found->imageTarget->value == target.value;
    }

    std::vector<std::byte> EncodeDirectory(
        std::span<relocations::RelocationSlot const> slots)
    {
        std::vector<std::byte> bytes;
        std::size_t begin{};
        while (begin < slots.size())
        {
            auto const page = slots[begin].location.value & ~0xfffu;
            auto end = begin;
            while (end < slots.size() && (slots[end].location.value & ~0xfffu) == page) ++end;

            auto const entryCount = end - begin;
            auto blockSize = static_cast<std::uint32_t>(
                sizeof(IMAGE_BASE_RELOCATION) + entryCount * sizeof(WORD));
            if ((blockSize & 3u) != 0) blockSize += sizeof(WORD);
            Append(bytes, IMAGE_BASE_RELOCATION{ page, blockSize });
            for (auto index = begin; index < end; ++index)
            {
                auto const offset = slots[index].location.value - page;
                auto const entry = static_cast<WORD>((IMAGE_REL_BASED_DIR64 << 12) | offset);
                Append(bytes, entry);
            }
            if ((entryCount & 1u) != 0) Append(bytes, WORD{});
            begin = end;
        }
        return bytes;
    }
}

namespace upx_killer::engine::pe::relocations
{
    RelocationRebuildResult RelocationReconstructor::Reconstruct(
        std::span<LoadedImageSnapshot const> snapshots,
        std::span<rebasing::SourceRelocationSlot const> sourceSlots,
        std::uint32_t sizeOfHeaders,
        std::uint32_t sizeOfImage,
        LoadedAddress preferredImageBase) noexcept
    {
        try
        {
            if (snapshots.size() != 3 || sizeOfHeaders >= sizeOfImage ||
                preferredImageBase.value == 0)
                return { std::nullopt, RelocationRebuildError::EvidenceInsufficient };
            for (std::size_t i = 0; i < snapshots.size(); ++i)
            {
                if (snapshots[i].loadedBase.value == 0 || snapshots[i].bytes.size() < sizeOfImage)
                    return { std::nullopt, RelocationRebuildError::InvalidInput };
                for (std::size_t j = 0; j < i; ++j)
                {
                    if (snapshots[i].loadedBase.value == snapshots[j].loadedBase.value)
                        return { std::nullopt, RelocationRebuildError::EvidenceInsufficient };
                }
            }

            RelocationRebuildPlan plan{};
            plan.preferredImageBase = preferredImageBase;
            for (std::uint32_t rva = sizeOfHeaders;
                static_cast<std::uint64_t>(rva) + sizeof(std::uint64_t) <= sizeOfImage;
                ++rva)
            {
                std::optional<std::uint64_t> target;
                bool candidate = true;
                for (auto const& snapshot : snapshots)
                {
                    auto const value = ReadU64(snapshot.bytes, rva);
                    if (value < snapshot.loadedBase.value)
                    {
                        candidate = false;
                        break;
                    }
                    auto const relative = value - snapshot.loadedBase.value;
                    if (relative >= sizeOfImage || (target && *target != relative))
                    {
                        candidate = false;
                        break;
                    }
                    target = relative;
                }
                if (!candidate || !target) continue;

                RelocationSlot slot{ { rva }, { static_cast<std::uint32_t>(*target) } };
                if (IsPackedResidue(sourceSlots, slot.location, slot.imageTarget)) continue;
                if (!plan.slots.empty() &&
                    static_cast<std::uint64_t>(plan.slots.back().location.value) + sizeof(std::uint64_t) > rva)
                    return { std::nullopt, RelocationRebuildError::CandidatesAmbiguous };
                plan.slots.push_back(slot);
            }
            if (plan.slots.empty())
                return { std::nullopt, RelocationRebuildError::NoRelocations };
            plan.directoryBytes = EncodeDirectory(plan.slots);
            if (plan.directoryBytes.empty())
                return { std::nullopt, RelocationRebuildError::InvalidInput };
            return { std::move(plan), RelocationRebuildError::None };
        }
        catch (...)
        {
            return { std::nullopt, RelocationRebuildError::InvalidInput };
        }
    }
}
