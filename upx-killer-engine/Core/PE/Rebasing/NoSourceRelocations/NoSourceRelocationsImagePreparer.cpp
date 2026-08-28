#include "Core/PE/Rebasing/NoSourceRelocations/NoSourceRelocationsImagePreparer.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>

namespace upx_killer::engine::pe::rebasing
{
    NoSourceRelocationsPreparationResult
    NoSourceRelocationsImagePreparer::Prepare(
        std::span<std::byte const> source,
        PeImageLayout const& layout,
        LoadedAddress requiredBase) noexcept
    {
        try
        {
            if (source.empty() ||
                requiredBase.value == 0 ||
                (requiredBase.value & 0xffffu) != 0 ||
                layout.preferredImageBase == 0 ||
                layout.ntHeaderOffset > source.size() ||
                sizeof(IMAGE_NT_HEADERS64) > source.size() - layout.ntHeaderOffset)
            {
                return {
                    std::nullopt,
                    NoSourceRelocationsPreparationError::InvalidInput
                };
            }

            auto const& directory =
                layout.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (directory.address.value != 0 || directory.size != 0)
            {
                return {
                    std::nullopt,
                    NoSourceRelocationsPreparationError::SourceRelocationsPresent
                };
            }

            NoSourceRelocationsImage result{
                std::vector<std::byte>{ source.begin(), source.end() },
                requiredBase,
            };
            auto const imageBaseOffset = layout.ntHeaderOffset +
                offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase);
            auto const characteristicsOffset = layout.ntHeaderOffset +
                offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                offsetof(IMAGE_OPTIONAL_HEADER64, DllCharacteristics);

            std::memcpy(
                result.bytes.data() + imageBaseOffset,
                &requiredBase.value,
                sizeof(requiredBase.value));
            WORD characteristics{};
            std::memcpy(
                &characteristics,
                result.bytes.data() + characteristicsOffset,
                sizeof(characteristics));
            characteristics &= static_cast<WORD>(~(
                IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
            std::memcpy(
                result.bytes.data() + characteristicsOffset,
                &characteristics,
                sizeof(characteristics));
            return {
                std::move(result),
                NoSourceRelocationsPreparationError::None
            };
        }
        catch (...)
        {
            return {
                std::nullopt,
                NoSourceRelocationsPreparationError::InvalidInput
            };
        }
    }
}
