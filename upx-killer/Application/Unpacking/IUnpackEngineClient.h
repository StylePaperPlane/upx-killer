#pragma once

#include "Core/Unpacking/UnpackTypes.h"

namespace upx_killer::application
{
    class IUnpackEngineClient
    {
    public:
        virtual ~IUnpackEngineClient() = default;
        [[nodiscard]] virtual engine::EngineResult Execute(engine::UnpackRequest const& request) noexcept = 0;
    };
}
