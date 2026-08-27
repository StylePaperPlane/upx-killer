#pragma once

#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <span>

namespace upx_killer::engine::pe::imports
{
    class ImportTableValidator final
    {
    public:
        [[nodiscard]] static bool Validate(
            std::span<std::byte const> image,
            PeImageLayout const& layout) noexcept;
    };
}
