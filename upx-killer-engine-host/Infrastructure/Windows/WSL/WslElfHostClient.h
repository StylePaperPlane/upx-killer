#pragma once

#include "Application/ELF/Hosting/IElfHostClient.h"
#include "Infrastructure/Windows/WSL/Bridge/WslFileBridge.h"
#include "Infrastructure/Windows/WSL/Hosting/WslApi.h"

namespace upx_killer::engine_host::wsl {

class WslElfHostClient final
    : public engine::application::elf_hosting::IElfHostClient {
 public:
  WslElfHostClient(WslApi const& api, std::wstring distribution,
                   std::filesystem::path linuxHostSource)
      : api_(api),
        distribution_(std::move(distribution)),
        linuxHostSource_(std::move(linuxHostSource)),
        bridge_(api) {}

  [[nodiscard]] contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      contracts::ProgressCallback const& progress,
      std::stop_token stopToken) const noexcept override;

 private:
  [[nodiscard]] std::uint32_t MakeExecutable(
      WslStagedJob const& staged) const noexcept;

  WslApi const& api_;
  std::wstring distribution_;
  std::filesystem::path linuxHostSource_;
  WslFileBridge bridge_;
};

}  // namespace upx_killer::engine_host::wsl
