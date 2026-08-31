#include "Infrastructure/Linux/Pipes/PosixPipeTransport.h"

#include <unistd.h>

#include <array>
#include <cerrno>
#include <span>
#include <vector>

namespace {
bool ReadExact(int handle, std::span<std::byte> bytes) noexcept {
  std::size_t offset{};
  while (offset < bytes.size()) {
    auto const count = read(handle, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<std::size_t>(count);
  }
  return true;
}

bool WriteExact(int handle, std::span<std::byte const> bytes) noexcept {
  std::size_t offset{};
  while (offset < bytes.size()) {
    auto const count = write(handle, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) return false;
    offset += static_cast<std::size_t>(count);
  }
  return true;
}
}  // namespace

namespace upx_killer::elf_host::pipes {
std::optional<contracts::protocol::EngineHostMessage>
PosixPipeTransport::Read() const noexcept {
  std::array<std::byte, contracts::protocol::FrameHeaderSize> headerBytes{};
  if (!ReadExact(input_, headerBytes)) return std::nullopt;
  auto header = contracts::protocol::EngineHostCodec::DecodeHeader(headerBytes);
  if (!header) return std::nullopt;
  std::vector<std::byte> payload(header->payloadSize);
  if (!ReadExact(input_, payload)) return std::nullopt;
  return contracts::protocol::EngineHostCodec::DecodePayload(*header, payload);
}

bool PosixPipeTransport::Write(
    contracts::protocol::EngineHostMessage const& message) const noexcept {
  auto frame = contracts::protocol::EngineHostCodec::Encode(message);
  return frame && WriteExact(output_, *frame);
}
}  // namespace upx_killer::elf_host::pipes
