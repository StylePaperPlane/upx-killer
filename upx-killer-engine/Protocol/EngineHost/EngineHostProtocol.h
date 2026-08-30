#pragma once

#include "Core/Unpacking/UnpackTypes.h"

#include <Windows.h>

#include <optional>

namespace upx_killer::engine::protocol {
constexpr std::uint32_t ProtocolVersion = 5;
constexpr std::uint32_t MaximumFrameSize = 1u << 20;

struct HostResponse {
  std::optional<EngineStage> progress;
  std::optional<EngineResult> result;
};

[[nodiscard]] bool WriteRequest(HANDLE pipe, UnpackRequest const& request) noexcept;
[[nodiscard]] bool ReadRequest(HANDLE pipe, UnpackRequest& request) noexcept;
[[nodiscard]] bool WriteProgress(HANDLE pipe, EngineStage stage) noexcept;
[[nodiscard]] bool WriteResult(HANDLE pipe, EngineResult const& result) noexcept;
[[nodiscard]] bool ReadResult(HANDLE pipe, EngineResult& result) noexcept;
[[nodiscard]] bool ReadResponse(HANDLE pipe, HostResponse& response) noexcept;
}
