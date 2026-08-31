#pragma once

#include "Infrastructure/Windows/WSL/Hosting/WslApi.h"

#include <filesystem>
#include <optional>
#include <string>

namespace upx_killer::engine_host::wsl {

class WslStagedJob final {
 public:
  WslStagedJob() = default;
  ~WslStagedJob();
  WslStagedJob(WslStagedJob const&) = delete;
  WslStagedJob& operator=(WslStagedJob const&) = delete;
  WslStagedJob(WslStagedJob&& other) noexcept;
  WslStagedJob& operator=(WslStagedJob&& other) noexcept;

  std::filesystem::path windowsRoot;
  std::string linuxRoot;
  std::string linuxTarget;
  std::string linuxOutput;
  std::string linuxHost;

  [[nodiscard]] std::uint32_t CopyOutputTo(
      std::filesystem::path const& destination) const noexcept;

 private:
  friend class WslFileBridge;
  bool ownsRoot_{};
  void Cleanup() noexcept;
};

struct WslStageResult {
  std::optional<WslStagedJob> job;
  std::uint32_t nativeCode{};
  std::string detailCode;
};

class WslFileBridge final {
 public:
  explicit WslFileBridge(WslApi const& api) : api_(api) {}

  [[nodiscard]] WslStageResult Stage(
      std::wstring_view distribution,
      std::filesystem::path const& linuxHostSource,
      std::filesystem::path const& targetSource) const noexcept;

 private:
  [[nodiscard]] std::uint32_t EnsureRunning(
      std::wstring_view distribution) const noexcept;

  WslApi const& api_;
};

}  // namespace upx_killer::engine_host::wsl
