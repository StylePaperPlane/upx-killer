#pragma once

#include "Core\PE\Imports\ImportTypes.h"
#include "Core\PE\Parsing\PeParser.h"

#include <cstddef>
#include <span>

namespace upx_killer::engine::pe::imports
{
    class ImportDiscovery final
    {
    public:
        [[nodiscard]] static ImportDiscoveryResult Discover(
            std::span<std::byte const> dumpedBytes,
            PeImageLayout const& sourceLayout,
            RuntimeModuleSnapshot const& runtime) noexcept;
    };
}
