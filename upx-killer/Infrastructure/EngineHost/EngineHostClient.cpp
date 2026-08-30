#include "pch.h"
#include "Infrastructure/EngineHost/EngineHostClient.h"

#include "Infrastructure/EngineHost/Process/EngineHostProcessSession.h"

#include <Windows.h>

#include <vector>

namespace upx_killer::infrastructure {
EngineHostClient::EngineHostClient(std::filesystem::path hostPath)
    : m_hostPath(std::move(hostPath)) {}

std::filesystem::path EngineHostClient::AdjacentHostPath() {
  std::vector<wchar_t> buffer(32768);
  auto const length = GetModuleFileNameW(
      nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length == buffer.size()) return {};
  return std::filesystem::path{
             std::wstring_view{buffer.data(), length}}
             .parent_path() /
         L"upx_killer_engine_host.exe";
}

std::vector<contracts::BackendManifest>
EngineHostClient::QueryCapabilities() noexcept {
  std::scoped_lock lock{m_capabilitiesMutex};
  if (m_capabilities) return *m_capabilities;
  auto result = EngineHostProcessSession::QueryCapabilities(m_hostPath);
  if (!result.succeeded) return {};
  m_capabilities = std::move(result.manifests);
  return *m_capabilities;
}

contracts::JobResult EngineHostClient::Execute(
    contracts::UnpackJobRequest const& request,
    ProgressCallback const& progress) noexcept {
  return EngineHostProcessSession::Execute(m_hostPath, request, progress);
}
}
