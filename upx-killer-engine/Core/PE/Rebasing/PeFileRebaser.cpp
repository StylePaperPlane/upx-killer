#include "Core/PE/Rebasing/PeFileRebaser.h"

#include <Windows.h>

#include <cstring>
#include <limits>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;

    std::optional<std::size_t> RvaToRaw(PeImageLayout const& layout, std::uint32_t rva, std::size_t size) noexcept
    {
        if (rva < layout.sizeOfHeaders)
        {
            if (size <= layout.sizeOfHeaders - rva) return rva;
            return std::nullopt;
        }
        for (auto const& section : layout.sections)
        {
            if (rva < section.virtualAddress.value) continue;
            auto const delta = static_cast<std::uint64_t>(rva) - section.virtualAddress.value;
            if (delta <= section.rawSize && size <= section.rawSize - delta)
                return static_cast<std::size_t>(section.rawOffset.value + delta);
        }
        return std::nullopt;
    }

    template <typename T>
    bool Read(std::span<std::byte const> bytes, std::size_t offset, T& value) noexcept
    {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
        std::memcpy(&value, bytes.data() + offset, sizeof(T));
        return true;
    }

    template <typename T>
    bool Write(std::vector<std::byte>& bytes, std::size_t offset, T const& value) noexcept
    {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
        std::memcpy(bytes.data() + offset, &value, sizeof(T));
        return true;
    }
}

namespace upx_killer::engine::pe::rebasing
{
    PeFileRebaseResult PeFileRebaser::Rebase(
        std::span<std::byte const> source,
        PeImageLayout const& layout,
        LoadedAddress requiredBase) noexcept
    {
        try
        {
            if (source.empty() || requiredBase.value == 0 || (requiredBase.value & 0xffffu) != 0 ||
                layout.preferredImageBase == 0 ||
                layout.ntHeaderOffset > source.size() ||
                sizeof(IMAGE_NT_HEADERS64) > source.size() - layout.ntHeaderOffset)
                return { std::nullopt, PeFileRebaseError::InvalidInput };

            auto const& directory = layout.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (directory.address.value == 0 || directory.size < sizeof(IMAGE_BASE_RELOCATION))
                return { std::nullopt, PeFileRebaseError::MissingRelocations };

            RebasedFileImage result{};
            result.bytes.assign(source.begin(), source.end());
            result.requiredBase = requiredBase;
            auto const delta = requiredBase.value - layout.preferredImageBase;
            std::uint32_t consumed{};
            while (consumed < directory.size)
            {
                auto blockRaw = RvaToRaw(layout, directory.address.value + consumed, sizeof(IMAGE_BASE_RELOCATION));
                IMAGE_BASE_RELOCATION block{};
                if (!blockRaw || !Read(source, *blockRaw, block) ||
                    block.SizeOfBlock < sizeof(block) ||
                    block.SizeOfBlock > directory.size - consumed ||
                    ((block.SizeOfBlock - sizeof(block)) % sizeof(WORD)) != 0)
                    return { std::nullopt, PeFileRebaseError::InvalidRelocationDirectory };

                auto const entryCount = (block.SizeOfBlock - sizeof(block)) / sizeof(WORD);
                for (std::uint32_t index = 0; index < entryCount; ++index)
                {
                    WORD entry{};
                    auto const entryRva = directory.address.value + consumed +
                        static_cast<std::uint32_t>(sizeof(IMAGE_BASE_RELOCATION)) +
                        index * static_cast<std::uint32_t>(sizeof(WORD));
                    auto entryRaw = RvaToRaw(layout, entryRva, sizeof(entry));
                    if (!entryRaw || !Read(source, *entryRaw, entry))
                        return { std::nullopt, PeFileRebaseError::InvalidRelocationDirectory };
                    auto const type = static_cast<std::uint16_t>(entry >> 12);
                    if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                    if (type != IMAGE_REL_BASED_DIR64)
                        return { std::nullopt, PeFileRebaseError::UnsupportedRelocationType };

                    auto const slot64 = static_cast<std::uint64_t>(block.VirtualAddress) + (entry & 0x0fffu);
                    if (slot64 > std::numeric_limits<std::uint32_t>::max())
                        return { std::nullopt, PeFileRebaseError::InvalidRelocationDirectory };
                    auto const slotRva = static_cast<std::uint32_t>(slot64);
                    auto slotRaw = RvaToRaw(layout, slotRva, sizeof(std::uint64_t));
                    std::uint64_t value{};
                    if (!slotRaw || !Read(source, *slotRaw, value))
                        return { std::nullopt, PeFileRebaseError::InvalidRelocationDirectory };

                    SourceRelocationSlot evidence{ { slotRva }, std::nullopt };
                    if (value >= layout.preferredImageBase &&
                        value - layout.preferredImageBase < layout.sizeOfImage)
                        evidence.imageTarget = RelativeVirtualAddress{
                            static_cast<std::uint32_t>(value - layout.preferredImageBase) };
                    result.sourceSlots.push_back(evidence);
                    value += delta;
                    if (!Write(result.bytes, *slotRaw, value))
                        return { std::nullopt, PeFileRebaseError::InvalidRelocationDirectory };
                }
                consumed += block.SizeOfBlock;
            }
            if (consumed != directory.size)
                return { std::nullopt, PeFileRebaseError::InvalidRelocationDirectory };

            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(result.bytes.data() + layout.ntHeaderOffset);
            nt->OptionalHeader.ImageBase = requiredBase.value;
            nt->OptionalHeader.DllCharacteristics &= static_cast<WORD>(~(
                IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
            nt->OptionalHeader.CheckSum = 0;
            return { std::move(result), PeFileRebaseError::None };
        }
        catch (...)
        {
            return { std::nullopt, PeFileRebaseError::InvalidInput };
        }
    }
}
