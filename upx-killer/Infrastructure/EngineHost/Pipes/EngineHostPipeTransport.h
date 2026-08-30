#pragma once

#include "Protocol/EngineHost/EngineHostCodec.h"

#include <Windows.h>

#include <optional>

namespace upx_killer::infrastructure {
class EngineHostPipeTransport final {
 public:
  EngineHostPipeTransport(HANDLE input, HANDLE output) noexcept
      : input_(input), output_(output) {}

  [[nodiscard]] bool Write(
      contracts::protocol::EngineHostMessage const& message) const noexcept;
  [[nodiscard]] std::optional<contracts::protocol::EngineHostMessage> Read() const noexcept;

 private:
  HANDLE input_{};
  HANDLE output_{};
};
}
