#pragma once

#include "Core/Unpacking/UnpackTypes.h"

#include <filesystem>

namespace upx_killer::engine::tests
{
    struct HostExecutionResult
    {
        bool protocolSucceeded{};
        EngineResult result;
    };

    [[nodiscard]] HostExecutionResult ExecuteThroughEngineHost(
        std::filesystem::path const& hostPath,
        UnpackRequest const& request) noexcept;
}
