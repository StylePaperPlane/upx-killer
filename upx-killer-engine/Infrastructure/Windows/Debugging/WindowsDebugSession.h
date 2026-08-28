#pragma once

#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/PE/Imports/ImportTypes.h"

#include <chrono>
#include <filesystem>
#include <functional>
#include <stop_token>
#include <span>
#include <variant>

namespace upx_killer::engine::debugging
{
    struct DebugLaunchRequest
    {
        std::filesystem::path targetPath;
        std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> oepTarget;
        std::uint32_t sizeOfImage{};
        std::chrono::milliseconds timeout{ 60'000 };
        bool collectRuntimeImports{};
        std::span<std::byte const> stagedTargetImage;
        std::optional<LoadedAddress> requiredImageBase;
    };

    struct DebugCaptureResult
    {
        EngineError error{ EngineError::None };
        std::uint32_t nativeError{};
        [[nodiscard]] bool Succeeded() const noexcept { return error == EngineError::None; }
    };

    using CaptureCallback = std::function<EngineError(
        dumping::IRemoteMemoryReader const&,
        dumping::LoadedImage const&,
        RelativeVirtualAddress,
        pe::imports::RuntimeModuleSnapshot const&)>;

    class WindowsDebugSession final
    {
    public:
        [[nodiscard]] static DebugCaptureResult Capture(
            DebugLaunchRequest const& request,
            CaptureCallback const& capture,
            std::stop_token stopToken = {}) noexcept;
    };
}
