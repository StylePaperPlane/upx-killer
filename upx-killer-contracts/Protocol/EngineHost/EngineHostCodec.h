#pragma once

#include "Protocol/EngineHost/EngineHostMessages.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace upx_killer::contracts::protocol {
constexpr std::uint32_t ProtocolVersion = 6;
constexpr std::uint32_t ProtocolMagic = 0x4b585055;
constexpr std::uint32_t MaximumFrameSize = 1u << 20;
constexpr std::size_t FrameHeaderSize = 16;

struct FrameHeader {
  std::uint32_t messageType{};
  std::uint32_t payloadSize{};
};

class EngineHostCodec final {
 public:
  [[nodiscard]] static std::optional<std::vector<std::byte>> Encode(
      EngineHostMessage const& message) noexcept;
  [[nodiscard]] static std::optional<FrameHeader> DecodeHeader(
      std::span<std::byte const> header) noexcept;
  [[nodiscard]] static std::optional<EngineHostMessage> DecodePayload(
      FrameHeader header, std::span<std::byte const> payload) noexcept;
};
}
