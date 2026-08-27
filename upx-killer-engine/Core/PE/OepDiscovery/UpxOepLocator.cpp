#include "Core/PE/OepDiscovery/UpxOepLocator.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;
    using namespace upx_killer::engine::pe::oep;

    constexpr std::uint32_t ImageScnMemExecute = 0x20000000;
    constexpr std::size_t MaximumTailSearch = 128;
    constexpr std::array<std::byte, 4> RegisterRestore{
        std::byte{ 0x5d }, std::byte{ 0x5f }, std::byte{ 0x5e }, std::byte{ 0x5b }
    };

    std::uint64_t SectionSpan(PeSection const& section) noexcept
    {
        return std::max<std::uint64_t>(section.virtualSize, section.rawSize);
    }

    bool ContainsRva(PeSection const& section, std::uint32_t rva) noexcept
    {
        auto const start = static_cast<std::uint64_t>(section.virtualAddress.value);
        auto const end = start + SectionSpan(section);
        return rva >= start && rva < end;
    }

    bool HasName(PeSection const& section, char const* expected) noexcept
    {
        auto const count = std::strlen(expected);
        return count <= section.name.size() && std::equal(expected, expected + count, section.name.begin());
    }

    bool HasUpxMarker(std::span<std::byte const> source) noexcept
    {
        constexpr std::array<std::byte, 4> marker{
            std::byte{ 'U' }, std::byte{ 'P' }, std::byte{ 'X' }, std::byte{ '!' }
        };
        return std::search(source.begin(), source.end(), marker.begin(), marker.end()) != source.end();
    }

    PeSection const* FindSection(PeImageLayout const& layout, std::uint32_t rva) noexcept
    {
        auto const iterator = std::find_if(layout.sections.begin(), layout.sections.end(),
            [rva](PeSection const& section) { return ContainsRva(section, rva); });
        return iterator == layout.sections.end() ? nullptr : &*iterator;
    }

    bool IsExecutableDestination(
        PeImageLayout const& layout,
        PeSection const* stub,
        std::uint32_t target) noexcept
    {
        if (target >= layout.sizeOfImage) return false;
        auto const* section = FindSection(layout, target);
        return section && section != stub && (section->characteristics & ImageScnMemExecute) != 0;
    }
}

namespace upx_killer::engine::pe::oep
{
    OepDiscoveryResult UpxOepLocator::Analyze(
        std::span<std::byte const> sourceBytes,
        PeImageLayout const& layout) noexcept
    {
        try
        {
            auto const* stub = FindSection(layout, layout.entryPoint.value);
            if (!stub || stub->rawSize == 0 || (stub->characteristics & ImageScnMemExecute) == 0)
                return { std::nullopt, OepDiscoveryError::UnsupportedPacker };

            bool hasUpx0{};
            bool hasUpx1{};
            bool hasSparseExecutableDestination{};
            for (auto const& section : layout.sections)
            {
                hasUpx0 = hasUpx0 || HasName(section, "UPX0");
                hasUpx1 = hasUpx1 || HasName(section, "UPX1");
                if (&section != stub && (section.characteristics & ImageScnMemExecute) != 0 &&
                    section.virtualSize != 0 &&
                    (section.rawSize == 0 || static_cast<std::uint64_t>(section.rawSize) * 4 < section.virtualSize))
                {
                    hasSparseExecutableDestination = true;
                }
            }

            if (!HasUpxMarker(sourceBytes) && !(hasUpx0 && hasUpx1) && !hasSparseExecutableDestination)
                return { std::nullopt, OepDiscoveryError::UnsupportedPacker };

            auto const entryDelta = static_cast<std::uint64_t>(layout.entryPoint.value) - stub->virtualAddress.value;
            auto const rawStart = static_cast<std::uint64_t>(stub->rawOffset.value) + entryDelta;
            auto const rawEnd = static_cast<std::uint64_t>(stub->rawOffset.value) + stub->rawSize;
            if (rawStart > rawEnd || rawEnd > sourceBytes.size())
                return { std::nullopt, OepDiscoveryError::OepNotFound };

            OepDiscoveryPlan plan{};
            plan.packedEntryPoint = layout.entryPoint;
            plan.stubStart = stub->virtualAddress;
            plan.stubSize = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                SectionSpan(*stub), std::numeric_limits<std::uint32_t>::max()));

            for (std::size_t offset = static_cast<std::size_t>(rawStart);
                 offset + RegisterRestore.size() + 5 <= rawEnd && plan.candidates.size() < MaximumOepCandidates;
                 ++offset)
            {
                if (!std::equal(RegisterRestore.begin(), RegisterRestore.end(), sourceBytes.begin() + offset))
                    continue;

                auto const searchEnd = std::min<std::size_t>(
                    static_cast<std::size_t>(rawEnd), offset + RegisterRestore.size() + MaximumTailSearch);
                for (auto transferOffset = offset + RegisterRestore.size();
                     transferOffset + 5 <= searchEnd && plan.candidates.size() < MaximumOepCandidates;
                     ++transferOffset)
                {
                    if (sourceBytes[transferOffset] != std::byte{ 0xe9 }) continue;
                    std::int32_t displacement{};
                    std::memcpy(&displacement, sourceBytes.data() + transferOffset + 1, sizeof(displacement));
                    auto const transferRva64 = static_cast<std::uint64_t>(stub->virtualAddress.value) +
                        (transferOffset - stub->rawOffset.value);
                    if (transferRva64 > std::numeric_limits<std::uint32_t>::max()) continue;
                    auto const target64 = static_cast<std::int64_t>(transferRva64 + 5) + displacement;
                    if (target64 < 0 || target64 > std::numeric_limits<std::uint32_t>::max()) continue;
                    auto const target = static_cast<std::uint32_t>(target64);
                    if (!IsExecutableDestination(layout, stub, target)) continue;

                    auto const transfer = static_cast<std::uint32_t>(transferRva64);
                    auto const duplicate = std::any_of(plan.candidates.begin(), plan.candidates.end(),
                        [transfer](OepTransferCandidate const& candidate) { return candidate.transfer.value == transfer; });
                    if (!duplicate) plan.candidates.push_back({ { transfer }, { target } });
                }
            }

            if (plan.candidates.empty()) return { std::nullopt, OepDiscoveryError::OepNotFound };
            return { std::move(plan), OepDiscoveryError::None };
        }
        catch (...)
        {
            return { std::nullopt, OepDiscoveryError::OepNotFound };
        }
    }
}
