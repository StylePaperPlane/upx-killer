#pragma once

#include "Core/Jobs/UnpackJob.h"

#include <filesystem>

namespace upx_killer::tests {
struct HostExecutionResult {
  bool protocolSucceeded{};
  contracts::JobResult result;
};

[[nodiscard]] HostExecutionResult ExecuteThroughEngineHost(std::filesystem::path const& hostPath,
                                                           contracts::UnpackJobRequest const& request) noexcept;
}
