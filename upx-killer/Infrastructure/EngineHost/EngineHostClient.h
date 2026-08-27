#pragma once

#include "Application/Unpacking/IUnpackEngineClient.h"

#include <filesystem>

namespace upx_killer::infrastructure
{
    class EngineHostClient final : public application::IUnpackEngineClient
    {
    public:
        explicit EngineHostClient(std::filesystem::path hostPath);
        [[nodiscard]] static std::filesystem::path AdjacentHostPath();
        [[nodiscard]] engine::EngineResult Execute(engine::UnpackRequest const& request) noexcept override;

    private:
        std::filesystem::path m_hostPath;
    };
}
