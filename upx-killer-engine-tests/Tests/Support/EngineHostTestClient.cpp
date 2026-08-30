#include "Tests/Support/EngineHostTestClient.h"

#include "Protocol/EngineHost/EngineHostCodec.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <limits>
#include <span>

namespace {
using namespace upx_killer;

bool WriteExact(HANDLE handle, std::span<std::byte const> bytes) {
  std::size_t offset{};
  while (offset < bytes.size()) {
    DWORD written{};
    auto const count = static_cast<DWORD>(std::min<std::size_t>(
        bytes.size() - offset, std::numeric_limits<DWORD>::max()));
    if (!WriteFile(handle, bytes.data() + offset, count, &written, nullptr) ||
        written == 0) return false;
    offset += written;
  }
  return true;
}

bool ReadExact(HANDLE handle, std::span<std::byte> bytes) {
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

std::optional<contracts::protocol::EngineHostMessage> ReadMessage(HANDLE pipe) {
  std::array<std::byte, contracts::protocol::FrameHeaderSize> headerBytes{};
  if (!ReadExact(pipe, headerBytes)) return std::nullopt;
  auto header = contracts::protocol::EngineHostCodec::DecodeHeader(headerBytes);
  if (!header) return std::nullopt;
  std::vector<std::byte> payload(header->payloadSize);
  if (!ReadExact(pipe, payload)) return std::nullopt;
  return contracts::protocol::EngineHostCodec::DecodePayload(*header, payload);
}

}

namespace upx_killer::tests {
HostExecutionResult ExecuteThroughEngineHost(std::filesystem::path const& hostPath,
                                             contracts::UnpackJobRequest const& request) noexcept {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE requestRead{}, requestWrite{}, resultRead{}, resultWrite{};
  if (!CreatePipe(&requestRead, &requestWrite, &security, 0) ||
      !CreatePipe(&resultRead, &resultWrite, &security, 0)) return {};
  SetHandleInformation(requestWrite, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(resultRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = requestRead;
  startup.hStdOutput = resultWrite;
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION process{};
  auto commandLine = L"\"" + hostPath.wstring() + L"\"";
  auto const created = CreateProcessW(
      hostPath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
      hostPath.parent_path().c_str(), &startup, &process);
  CloseHandle(requestRead);
  CloseHandle(resultWrite);
  if (!created) {
    CloseHandle(requestWrite);
    CloseHandle(resultRead);
    return {};
  }

  auto frame = contracts::protocol::EngineHostCodec::Encode(
      contracts::protocol::ExecuteJobMessage{request});
  auto const wrote = frame && WriteExact(requestWrite, *frame);
  CloseHandle(requestWrite);
  contracts::JobResult result{};
  bool read{};
  for (;;) {
    auto message = ReadMessage(resultRead);
    if (!message) break;
    if (auto* completed =
            std::get_if<contracts::protocol::ResultMessage>(&*message)) {
      result = std::move(completed->result);
      read = true;
      break;
    }
  }
  CloseHandle(resultRead);
  if (WaitForSingleObject(process.hProcess, 65'000) == WAIT_TIMEOUT)
    TerminateProcess(process.hProcess, WAIT_TIMEOUT);
  CloseHandle(process.hThread);
  CloseHandle(process.hProcess);
  return {wrote && read, std::move(result)};
}
}
