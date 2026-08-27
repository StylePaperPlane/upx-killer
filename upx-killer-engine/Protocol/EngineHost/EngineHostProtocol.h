#pragma once

#include "Core/Unpacking/UnpackTypes.h"

#include <Windows.h>

namespace upx_killer::engine::protocol
{
    constexpr std::uint32_t ProtocolVersion = 2;
    constexpr std::uint32_t MaximumFrameSize = 1u << 20;

    [[nodiscard]] bool WriteRequest(HANDLE pipe, UnpackRequest const& request) noexcept;
    [[nodiscard]] bool ReadRequest(HANDLE pipe, UnpackRequest& request) noexcept;
    [[nodiscard]] bool WriteResult(HANDLE pipe, EngineResult const& result) noexcept;
    [[nodiscard]] bool ReadResult(HANDLE pipe, EngineResult& result) noexcept;
}
