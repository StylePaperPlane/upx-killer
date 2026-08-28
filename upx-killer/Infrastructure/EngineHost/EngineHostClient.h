#pragma once

#include "Application/Unpacking/IUnpackEngineClient.h"
#include "Application/TemporaryFiles/TemporaryFileSettings.h"

#include <filesystem>
#include <memory>

namespace upx_killer::infrastructure
{
    class EngineHostClient final : public application::IUnpackEngineClient
    {
    public:
        EngineHostClient(
            std::filesystem::path hostPath,
            std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore);
        [[nodiscard]] static std::filesystem::path AdjacentHostPath();
        [[nodiscard]] engine::EngineResult Execute(
            engine::UnpackRequest const& request,
            ProgressCallback const& progress = {}) noexcept override;

    private:
        std::filesystem::path m_hostPath;
        std::shared_ptr<application::ITemporaryFileSettingsStore> m_settingsStore;
    };
}
