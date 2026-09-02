#pragma once

#include "Protocol/EngineHost/EngineHostCodec.h"

#include <Windows.h>

#include <optional>
#include <stop_token>

namespace upx_killer::engine_host {
class EngineHostPipeTransport final {
 public:
  explicit EngineHostPipeTransport(HANDLE input, HANDLE output)
      : input_(input), output_(output) {}

  [[nodiscard]] std::optional<contracts::protocol::EngineHostMessage> Read(
      std::stop_token stopToken = {}) const noexcept;
  [[nodiscard]] bool Write(
      contracts::protocol::EngineHostMessage const& message) const noexcept;

 private:
  HANDLE input_{};
  HANDLE output_{};
};
}
