#pragma once

#include <Windows.h>

#include <cstdint>
#include <filesystem>

namespace upx_killer::engine::verification
{
    struct ExecutableVerificationResult
    {
        bool completed{};
        bool timedOut{};
        std::uint32_t exitCode{};
        std::uint32_t nativeError{};
    };

    class ExecutableVerifier final
    {
    public:
        [[nodiscard]] static ExecutableVerificationResult Verify(
            std::filesystem::path const& executable,
            std::filesystem::path const& workingDirectory,
            std::uint32_t timeoutMilliseconds) noexcept;
    };
}
