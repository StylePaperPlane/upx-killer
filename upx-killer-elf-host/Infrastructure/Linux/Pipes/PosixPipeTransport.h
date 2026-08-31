#pragma once

#include "Protocol/EngineHost/EngineHostCodec.h"

#include <optional>

namespace upx_killer::elf_host::pipes {
class PosixPipeTransport final {
 public:
  PosixPipeTransport(int input, int output) : input_(input), output_(output) {}

  [[nodiscard]] std::optional<contracts::protocol::EngineHostMessage> Read()
      const noexcept;
  [[nodiscard]] bool Write(
      contracts::protocol::EngineHostMessage const& message) const noexcept;

 private:
  int input_{};
  int output_{};
};
}  // namespace upx_killer::elf_host::pipes
