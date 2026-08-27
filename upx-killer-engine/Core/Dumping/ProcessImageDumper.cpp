#include "Core/Dumping/ProcessImageDumper.h"

#include <algorithm>
#include <limits>

namespace upx_killer::engine::dumping
{
    DumpResult ProcessImageDumper::Dump(
        IRemoteMemoryReader const& reader,
        LoadedImage loadedImage,
        pe::PeImageLayout const& layout,
        DumpLimits limits) noexcept
    {
        if (loadedImage.size != layout.sizeOfImage || loadedImage.size == 0 ||
            loadedImage.size > limits.maximumImageSize || loadedImage.size > std::numeric_limits<std::size_t>::max())
            return { std::nullopt, EngineError::DumpIncomplete };

        try
        {
            DumpedImage result{};
            result.loadedBase = loadedImage.base;
            result.bytes.resize(static_cast<std::size_t>(loadedImage.size));

            std::uint64_t offset = 0;
            while (offset < loadedImage.size)
            {
                auto const current = LoadedAddress{ loadedImage.base.value + offset };
                auto const region = reader.Query(current);
                if (region.size == 0 || region.base.value > current.value ||
                    current.value - region.base.value >= region.size)
                    return { std::nullopt, EngineError::ReadMemoryFailed };

                auto const regionEnd = region.base.value + region.size;
                auto const remaining = loadedImage.size - offset;
                auto const chunk64 = std::min(remaining, regionEnd - current.value);
                auto const chunk = static_cast<std::size_t>(chunk64);
                if (!region.readable)
                {
                    result.warnings.emplace_back("UnreadableMemoryRegionZeroFilled");
                    offset += chunk64;
                    continue;
                }

                auto destination = std::span<std::byte>{ result.bytes }.subspan(static_cast<std::size_t>(offset), chunk);
                auto const read = reader.Read(current, destination);
                if (read < chunk)
                {
                    result.warnings.emplace_back("PartialMemoryReadZeroFilled");
                }
                if (read == 0)
                {
                    result.warnings.emplace_back("UnreadableMemoryRegionZeroFilled");
                }
                offset += chunk64;
            }
            return { std::move(result), EngineError::None };
        }
        catch (...)
        {
            return { std::nullopt, EngineError::ReadMemoryFailed };
        }
    }
}
