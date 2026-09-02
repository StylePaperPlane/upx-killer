#pragma once

#include "Infrastructure/Windows/WSL/Hosting/WslApi.h"
#include "Protocol/EngineHost/EngineHostMessages.h"

#include <memory>
#include <optional>

namespace upx_killer::engine_host::wsl {

struct WslSessionStartResult;

class WslHostProcessSession final {
 public:
  ~WslHostProcessSession();
  WslHostProcessSession(WslHostProcessSession const&) = delete;
  WslHostProcessSession& operator=(WslHostProcessSession const&) = delete;

  [[nodiscard]] static WslSessionStartResult Start(
      WslApi const& api, std::wstring_view distribution,
      std::wstring_view command) noexcept;
  [[nodiscard]] bool Write(
      contracts::protocol::EngineHostMessage const& message) const noexcept;
  [[nodiscard]] std::optional<contracts::protocol::EngineHostMessage> Read(
      std::stop_token stopToken = {}) const noexcept;

 private:
  WslHostProcessSession(HANDLE process, HANDLE inputWrite, HANDLE outputRead)
      : process_(process), inputWrite_(inputWrite), outputRead_(outputRead) {}

  HANDLE process_{};
  HANDLE inputWrite_{};
  HANDLE outputRead_{};
};

struct WslSessionStartResult {
  std::unique_ptr<WslHostProcessSession> session;
  std::uint32_t nativeCode{};
};

}  // namespace upx_killer::engine_host::wsl
