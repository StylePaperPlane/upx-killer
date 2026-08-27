#pragma once

#include "Core\Unpacking\UnpackTypes.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace upx_killer::engine::pe::imports
{
    struct RuntimeExport
    {
        std::string moduleName;
        LoadedAddress address;
        std::optional<std::string> name;
        std::optional<std::uint16_t> ordinal;
        bool executable{};
        std::optional<std::string> forwarder;
    };

    struct RuntimeModule
    {
        std::string moduleName;
        LoadedAddress base;
        std::uint32_t imageSize{};
        std::vector<RuntimeExport> exports;
    };

    struct RuntimeModuleSnapshot
    {
        std::vector<RuntimeModule> modules;
    };

    enum class ExportParseError
    {
        None,
        InvalidImage,
        Truncated,
        InvalidDirectory,
        LimitExceeded,
    };

    enum class ImportDiscoveryError
    {
        None,
        ImportsNotFound,
        ImportsAmbiguous,
        InvalidInput,
    };

    struct ImportDiscoveryResult
    {
        std::optional<ImportRebuildPlan> plan;
        ImportDiscoveryError error{ ImportDiscoveryError::None };
        std::vector<std::string> warnings;

        [[nodiscard]] bool Succeeded() const noexcept { return plan.has_value(); }
    };
}
