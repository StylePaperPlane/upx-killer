#include "Infrastructure/Windows/Pipes/EngineHostPipeTransport.h"

#include <algorithm>
#include <array>
#include <limits>
#include <span>
#include <vector>

namespace {
bool ReadExact(HANDLE handle, std::span<std::byte> bytes) noexcept {
  std::size_t offset{};
  while (offset < bytes.size()) {
    DWORD read{};
    auto const count = static_cast<DWORD>(std::min<std::size_t>(
        bytes.size() - offset, std::numeric_limits<DWORD>::max()));
    if (!ReadFile(handle, bytes.data() + offset, count, &read, nullptr) || read == 0)
      return false;
    offset += read;
  }
  return true;
}

bool WriteExact(HANDLE handle, std::span<std::byte const> bytes) noexcept {
  std::size_t offset{};
  while (offset < bytes.size()) {
    DWORD written{};
    auto const count = static_cast<DWORD>(std::min<std::size_t>(
        bytes.size() - offset, std::numeric_limits<DWORD>::max()));
    if (!WriteFile(handle, bytes.data() + offset, count, &written, nullptr) ||
        written == 0)
      return false;
    offset += written;
  }
  return true;
}
}

namespace upx_killer::engine_host {
std::optional<contracts::protocol::EngineHostMessage>
EngineHostPipeTransport::Read() const noexcept {
  std::array<std::byte, contracts::protocol::FrameHeaderSize> headerBytes{};
  if (!ReadExact(input_, headerBytes)) return std::nullopt;
  auto header = contracts::protocol::EngineHostCodec::DecodeHeader(headerBytes);
  if (!header) return std::nullopt;
  std::vector<std::byte> payload(header->payloadSize);
  if (!ReadExact(input_, payload)) return std::nullopt;
  return contracts::protocol::EngineHostCodec::DecodePayload(*header, payload);
}

bool EngineHostPipeTransport::Write(
    contracts::protocol::EngineHostMessage const& message) const noexcept {
  auto frame = contracts::protocol::EngineHostCodec::Encode(message);
  return frame && WriteExact(output_, *frame);
}
}
