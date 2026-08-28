#pragma once

#include "Core/Unpacking/UnpackTypes.h"

#include <functional>
#include <stop_token>

namespace upx_killer::engine::application
{
    using ProgressCallback = std::function<void(EngineStage)>;

    class UnpackEngine final
    {
    public:
        [[nodiscard]] static EngineResult Execute(
            UnpackRequest const& request,
            ProgressCallback const& progress,
            std::stop_token stopToken = {}) noexcept;
    };
}
