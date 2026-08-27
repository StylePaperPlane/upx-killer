#pragma once

#include "Core\PE\Imports\ImportTypes.h"

#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace upx_killer::engine::pe::imports
{
    struct ExportParseResult
    {
        std::vector<RuntimeExport> exports;
        ExportParseError error{ ExportParseError::None };
        [[nodiscard]] bool Succeeded() const noexcept { return error == ExportParseError::None; }
    };

    class PeExportParser final
    {
    public:
        [[nodiscard]] static ExportParseResult Parse(
            std::span<std::byte const> image,
            LoadedAddress base,
            std::string moduleName) noexcept;
    };
}
