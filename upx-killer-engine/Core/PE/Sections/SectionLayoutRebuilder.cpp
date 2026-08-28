#include "Core/PE/Sections/SectionLayoutRebuilder.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string_view>

namespace
{
    using namespace upx_killer::engine;
    using namespace upx_killer::engine::pe;
    using namespace upx_killer::engine::pe::sections;

    constexpr std::size_t MaximumSections = 95;

    enum class SectionRole : std::size_t
    {
        Text,
        ReadOnlyData,
        WritableData,
        ExceptionData,
        ResourceData,
        ImportAddressTable,
        Count,
    };

    struct AddressRange
    {
        std::uint32_t begin{};
        std::uint32_t end{};
    };

    bool IsPowerOfTwo(std::uint32_t value) noexcept
    {
        return value != 0 && (value & (value - 1)) == 0;
    }

    std::uint32_t AlignDown(std::uint32_t value, std::uint32_t alignment) noexcept
    {
        return value & ~(alignment - 1);
    }

    bool AlignUp(std::uint32_t value, std::uint32_t alignment, std::uint32_t& aligned) noexcept
    {
        auto const mask = alignment - 1;
        if (value > std::numeric_limits<std::uint32_t>::max() - mask) return false;
        aligned = (value + mask) & ~mask;
        return true;
    }

    bool Overlaps(AddressRange const& left, AddressRange const& right) noexcept
    {
        return left.begin < right.end && right.begin < left.end;
    }

    bool ValidDirectory(PeDataDirectory const& directory, std::uint32_t imageSize) noexcept
    {
        return directory.address.value != 0 && directory.size != 0 &&
            directory.address.value < imageSize && directory.size <= imageSize - directory.address.value;
    }

    AddressRange DirectoryRange(PeDataDirectory const& directory) noexcept
    {
        return { directory.address.value, directory.address.value + directory.size };
    }

    std::vector<AddressRange> DiscoverCodeRanges(
        PeImageLayout const& source,
        SectionLayoutInput const& input)
    {
        std::vector<AddressRange> ranges;
        auto minimum = input.oep.value;
        auto maximum = input.oep.value + 1;
        bool hasRuntimeFunction{};

        auto const& exception = source.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ValidDirectory(exception, source.sizeOfImage))
        {
            auto const count = exception.size / sizeof(RUNTIME_FUNCTION);
            for (std::size_t index = 0; index < count; ++index)
            {
                RUNTIME_FUNCTION function{};
                auto const offset = static_cast<std::size_t>(exception.address.value) + index * sizeof(function);
                if (offset > input.loadedImage.size() || sizeof(function) > input.loadedImage.size() - offset) break;
                std::memcpy(&function, input.loadedImage.data() + offset, sizeof(function));
                if (function.BeginAddress >= function.EndAddress || function.EndAddress > source.sizeOfImage) continue;
                minimum = std::min(minimum, static_cast<std::uint32_t>(function.BeginAddress));
                maximum = std::max(maximum, static_cast<std::uint32_t>(function.EndAddress));
                hasRuntimeFunction = true;
            }
        }

        if (!hasRuntimeFunction)
        {
            auto const containing = std::find_if(source.sections.begin(), source.sections.end(), [&](PeSection const& section) {
                auto const extent = std::max(section.virtualSize, section.rawSize);
                return input.oep.value >= section.virtualAddress.value &&
                    input.oep.value - section.virtualAddress.value < extent;
            });
            if (containing != source.sections.end())
            {
                minimum = containing->virtualAddress.value;
                maximum = containing->virtualAddress.value + std::max(containing->virtualSize, containing->rawSize);
            }
        }

        std::uint32_t end{};
        if (!AlignUp(maximum, source.sectionAlignment, end)) return {};
        ranges.push_back({ AlignDown(minimum, source.sectionAlignment), std::min(end, source.sizeOfImage) });

        auto const& tlsDirectory = source.directories[IMAGE_DIRECTORY_ENTRY_TLS];
        if (ValidDirectory(tlsDirectory, source.sizeOfImage) && tlsDirectory.size >= sizeof(IMAGE_TLS_DIRECTORY64))
        {
            IMAGE_TLS_DIRECTORY64 tls{};
            auto const offset = static_cast<std::size_t>(tlsDirectory.address.value);
            if (offset <= input.loadedImage.size() && sizeof(tls) <= input.loadedImage.size() - offset)
            {
                std::memcpy(&tls, input.loadedImage.data() + offset, sizeof(tls));
                if (tls.AddressOfCallBacks >= input.loadedBase.value)
                {
                    auto const callbackTable = tls.AddressOfCallBacks - input.loadedBase.value;
                    if (callbackTable < source.sizeOfImage)
                    {
                        for (std::size_t index = 0; index < 1024; ++index)
                        {
                            auto const callbackOffset = callbackTable + index * sizeof(std::uint64_t);
                            if (callbackOffset > input.loadedImage.size() ||
                                sizeof(std::uint64_t) > input.loadedImage.size() - callbackOffset)
                                break;
                            std::uint64_t callback{};
                            std::memcpy(&callback, input.loadedImage.data() + callbackOffset, sizeof(callback));
                            if (callback == 0) break;
                            if (callback < input.loadedBase.value || callback - input.loadedBase.value >= source.sizeOfImage)
                                continue;
                            auto const rva = static_cast<std::uint32_t>(callback - input.loadedBase.value);
                            ranges.push_back({
                                AlignDown(rva, source.sectionAlignment),
                                std::min(AlignDown(rva, source.sectionAlignment) + source.sectionAlignment, source.sizeOfImage) });
                        }
                    }
                }
            }
        }
        return ranges;
    }

    bool DiscoverIatRanges(
        PeImageLayout const& source,
        ImportRebuildPlan const* imports,
        std::vector<AddressRange>& ranges) noexcept
    {
        if (!imports) return true;
        for (auto const& module : imports->modules)
        {
            if (module.symbols.empty()) return false;
            auto const thunkCount = module.symbols.size() + 1;
            if (thunkCount > std::numeric_limits<std::uint32_t>::max() / sizeof(std::uint64_t)) return false;
            auto const size = static_cast<std::uint32_t>(thunkCount * sizeof(std::uint64_t));
            if (module.firstThunk.value >= source.sizeOfImage || size > source.sizeOfImage - module.firstThunk.value)
                return false;
            ranges.push_back({ module.firstThunk.value, module.firstThunk.value + size });
        }
        return true;
    }

    SectionRole Classify(
        AddressRange const& page,
        PeSection const& sourceSection,
        std::vector<AddressRange> const& code,
        std::vector<AddressRange> const& iat,
        PeImageLayout const& source) noexcept
    {
        if (std::any_of(code.begin(), code.end(), [&](AddressRange const& range) { return Overlaps(page, range); }))
            return SectionRole::Text;
        if (std::any_of(iat.begin(), iat.end(), [&](AddressRange const& range) { return Overlaps(page, range); }))
            return SectionRole::ImportAddressTable;

        auto const& exception = source.directories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ValidDirectory(exception, source.sizeOfImage) && Overlaps(page, DirectoryRange(exception)))
            return SectionRole::ExceptionData;

        auto const& resource = source.directories[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        if (ValidDirectory(resource, source.sizeOfImage) && Overlaps(page, DirectoryRange(resource)))
            return SectionRole::ResourceData;

        auto const isReadOnly = (sourceSection.characteristics & IMAGE_SCN_MEM_READ) != 0 &&
            (sourceSection.characteristics & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) == 0;
        return isReadOnly ? SectionRole::ReadOnlyData : SectionRole::WritableData;
    }

    std::string_view BaseName(SectionRole role) noexcept
    {
        switch (role)
        {
        case SectionRole::Text: return ".text";
        case SectionRole::ReadOnlyData: return ".rdata";
        case SectionRole::WritableData: return ".data";
        case SectionRole::ExceptionData: return ".pdata";
        case SectionRole::ResourceData: return ".rsrc";
        case SectionRole::ImportAddressTable: return ".iat";
        default: return ".data";
        }
    }

    std::uint32_t Characteristics(SectionRole role) noexcept
    {
        switch (role)
        {
        case SectionRole::Text:
            return IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        case SectionRole::WritableData:
        case SectionRole::ImportAddressTable:
            return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        default:
            return IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        }
    }

    std::array<char, 8> MakeName(SectionRole role, std::size_t ordinal)
    {
        std::array<char, 8> name{};
        auto const base = BaseName(role);
        std::copy(base.begin(), base.end(), name.begin());
        if (ordinal != 0)
        {
            auto const digit = static_cast<char>('0' + std::min<std::size_t>(ordinal, 9));
            name[std::min<std::size_t>(base.size(), name.size() - 1)] = digit;
        }
        return name;
    }
}

namespace upx_killer::engine::pe::sections
{
    SectionLayoutResult SectionLayoutRebuilder::Build(
        PeImageLayout const& source,
        SectionLayoutInput const& input) noexcept
    {
        try
        {
            if (source.sections.empty() || source.sizeOfImage == 0 ||
                !IsPowerOfTwo(source.sectionAlignment) || !IsPowerOfTwo(source.fileAlignment) ||
                input.loadedImage.size() < source.sizeOfImage || input.oep.value >= source.sizeOfImage)
                return { std::nullopt, SectionLayoutError::InvalidInput };

            auto const codeRanges = DiscoverCodeRanges(source, input);
            if (codeRanges.empty()) return { std::nullopt, SectionLayoutError::InvalidInput };
            std::vector<AddressRange> iatRanges;
            if (!DiscoverIatRanges(source, input.imports, iatRanges))
                return { std::nullopt, SectionLayoutError::InvalidInput };

            struct PlannedRange
            {
                AddressRange range;
                SectionRole role;
            };
            std::vector<PlannedRange> ranges;
            for (auto const& original : source.sections)
            {
                auto const extent = std::max(original.virtualSize, original.rawSize);
                if (extent == 0 || original.virtualAddress.value >= source.sizeOfImage ||
                    original.virtualAddress.value % source.sectionAlignment != 0)
                    return { std::nullopt, SectionLayoutError::InvalidInput };
                auto const end = std::min<std::uint64_t>(
                    static_cast<std::uint64_t>(original.virtualAddress.value) + extent,
                    source.sizeOfImage);
                auto cursor = original.virtualAddress.value;
                while (cursor < end)
                {
                    auto const pageEnd = static_cast<std::uint32_t>(
                        std::min<std::uint64_t>(static_cast<std::uint64_t>(cursor) + source.sectionAlignment, end));
                    AddressRange page{ cursor, pageEnd };
                    auto const role = Classify(page, original, codeRanges, iatRanges, source);
                    if (!ranges.empty() && ranges.back().role == role && ranges.back().range.end == page.begin)
                        ranges.back().range.end = page.end;
                    else
                        ranges.push_back({ page, role });
                    cursor = pageEnd;
                }
            }
            if (ranges.empty()) return { std::nullopt, SectionLayoutError::InvalidInput };
            if (ranges.size() > MaximumSections) return { std::nullopt, SectionLayoutError::TooManySections };

            SectionLayoutPlan plan{};
            plan.sections.reserve(ranges.size());
            std::array<std::size_t, static_cast<std::size_t>(SectionRole::Count)> nameCounts{};
            for (auto const& range : ranges)
            {
                auto const roleIndex = static_cast<std::size_t>(range.role);
                RebuiltSection section{};
                section.name = MakeName(range.role, nameCounts[roleIndex]++);
                section.virtualAddress = { range.range.begin };
                section.virtualSize = range.range.end - range.range.begin;
                section.characteristics = Characteristics(range.role);
                plan.sections.push_back(section);
            }
            return { std::move(plan), SectionLayoutError::None };
        }
        catch (...)
        {
            return { std::nullopt, SectionLayoutError::InvalidInput };
        }
    }
}
