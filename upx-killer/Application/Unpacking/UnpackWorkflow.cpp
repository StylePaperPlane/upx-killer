#include "pch.h"
#include "Application/Unpacking/UnpackWorkflow.h"

namespace upx_killer::application
{
    UnpackWorkflow::UnpackWorkflow(std::shared_ptr<IUnpackEngineClient> client)
        : m_client(std::move(client))
    {
    }

    UnpackResult UnpackWorkflow::Start(
        std::filesystem::path const& targetPath,
        std::optional<engine::RelativeVirtualAddress> oep) const noexcept
    {
        if (!m_client) return { UnpackOutcome::Failed, {}, {} };

        engine::UnpackRequest request{};
        request.targetPath = targetPath;
        request.oep = oep;
        auto result = m_client->Execute(request);
        if (result.outcome == engine::EngineOutcome::Partial && result.artifact)
            return { UnpackOutcome::Partial, result.artifact->path, result.artifact->warnings };
        if (result.outcome == engine::EngineOutcome::Completed && result.artifact)
            return { UnpackOutcome::Succeeded, result.artifact->path, result.artifact->warnings };
        if (result.outcome == engine::EngineOutcome::NeedsOep)
            return { UnpackOutcome::NeedsOep, {}, {} };
        if (result.outcome == engine::EngineOutcome::UnsupportedTarget)
        {
            return {
                result.error == engine::EngineError::UnsupportedPacker
                    ? UnpackOutcome::UnsupportedPacker : UnpackOutcome::Unsupported,
                {}, {}
            };
        }
        if (result.outcome == engine::EngineOutcome::OepNotFound)
            return { UnpackOutcome::OepNotFound, {}, {} };
        if (result.error == engine::EngineError::ImportsNotFound)
            return { UnpackOutcome::ImportsNotFound, {}, {} };
        if (result.error == engine::EngineError::ImportsAmbiguous)
            return { UnpackOutcome::ImportsAmbiguous, {}, {} };
        return { UnpackOutcome::Failed, {}, {} };
    }
}
