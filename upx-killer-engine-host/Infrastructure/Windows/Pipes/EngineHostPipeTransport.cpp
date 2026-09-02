#include "Infrastructure/Windows/Pipes/EngineHostPipeTransport.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <span>
#include <vector>
#include <thread>

namespace {
bool ReadExact(HANDLE handle, std::span<std::byte> bytes,
               std::stop_token stopToken) noexcept {
  std::size_t offset{};
  while (offset < bytes.size()) {
    if (stopToken.stop_requested()) {
      SetLastError(ERROR_CANCELLED);
      return false;
    }
    DWORD available{};
    if (!PeekNamedPipe(handle, nullptr, 0, nullptr, &available, nullptr))
      return false;
    if (available == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
      continue;
    }
    DWORD read{};
    auto const count = static_cast<DWORD>(std::min<std::size_t>(
        bytes.size() - offset,
        std::min<std::size_t>(available,
                              std::numeric_limits<DWORD>::max())));
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
EngineHostPipeTransport::Read(std::stop_token stopToken) const noexcept {
  std::array<std::byte, contracts::protocol::FrameHeaderSize> headerBytes{};
  if (!ReadExact(input_, headerBytes, stopToken)) return std::nullopt;
  auto header = contracts::protocol::EngineHostCodec::DecodeHeader(headerBytes);
  if (!header) return std::nullopt;
  std::vector<std::byte> payload(header->payloadSize);
  if (!ReadExact(input_, payload, stopToken)) return std::nullopt;
  return contracts::protocol::EngineHostCodec::DecodePayload(*header, payload);
}

bool EngineHostPipeTransport::Write(
    contracts::protocol::EngineHostMessage const& message) const noexcept {
  auto frame = contracts::protocol::EngineHostCodec::Encode(message);
  return frame && WriteExact(output_, *frame);
}
}
