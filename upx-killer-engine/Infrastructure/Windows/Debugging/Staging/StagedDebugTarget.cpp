#include "Infrastructure/Windows/Debugging/Staging/StagedDebugTarget.h"

#include <Windows.h>

#include <atomic>
#include <fstream>
#include <utility>

namespace
{
    std::atomic_uint64_t Sequence{};
}

namespace upx_killer::engine::debugging::staging
{
    StagedDebugTarget::~StagedDebugTarget()
    {
        Reset();
    }

    StagedDebugTarget::StagedDebugTarget(StagedDebugTarget&& other) noexcept
        : directory_(std::move(other.directory_)),
          executablePath_(std::move(other.executablePath_))
    {
        other.directory_.clear();
        other.executablePath_.clear();
    }

    StagedDebugTarget& StagedDebugTarget::operator=(StagedDebugTarget&& other) noexcept
    {
        if (this != &other)
        {
            Reset();
            directory_ = std::move(other.directory_);
            executablePath_ = std::move(other.executablePath_);
            other.directory_.clear();
            other.executablePath_.clear();
        }
        return *this;
    }

    std::optional<StagedDebugTarget> StagedDebugTarget::Create(
        std::filesystem::path const& sourcePath,
        std::span<std::byte const> image,
        std::uint32_t& nativeError) noexcept
    {
        nativeError = ERROR_SUCCESS;
        try
        {
            if (sourcePath.filename().empty() || image.empty())
            {
                nativeError = ERROR_INVALID_PARAMETER;
                return std::nullopt;
            }
            auto const root = std::filesystem::temp_directory_path() /
                L"upx-killer" / L"debug-staging";
            std::error_code error;
            std::filesystem::create_directories(root, error);
            if (error)
            {
                nativeError = static_cast<std::uint32_t>(error.value());
                return std::nullopt;
            }

            StagedDebugTarget staged;
            for (unsigned attempt = 0; attempt < 32; ++attempt)
            {
                auto const id = Sequence.fetch_add(1, std::memory_order_relaxed);
                auto const name = L"stage-" + std::to_wstring(GetCurrentProcessId()) +
                    L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(id);
                staged.directory_ = root / name;
                if (std::filesystem::create_directory(staged.directory_, error)) break;
                staged.directory_.clear();
                if (error && error != std::errc::file_exists)
                {
                    nativeError = static_cast<std::uint32_t>(error.value());
                    return std::nullopt;
                }
                error.clear();
            }
            if (staged.directory_.empty())
            {
                nativeError = ERROR_ALREADY_EXISTS;
                return std::nullopt;
            }

            staged.executablePath_ = staged.directory_ / sourcePath.filename();
            std::ofstream output(staged.executablePath_, std::ios::binary | std::ios::trunc);
            if (!output)
            {
                nativeError = ERROR_WRITE_FAULT;
                return std::nullopt;
            }
            output.write(
                reinterpret_cast<char const*>(image.data()),
                static_cast<std::streamsize>(image.size()));
            if (!output)
            {
                nativeError = ERROR_WRITE_FAULT;
                return std::nullopt;
            }
            output.close();
            return staged;
        }
        catch (...)
        {
            nativeError = ERROR_WRITE_FAULT;
            return std::nullopt;
        }
    }

    void StagedDebugTarget::Reset() noexcept
    {
        if (directory_.empty()) return;
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
        directory_.clear();
        executablePath_.clear();
    }
}
