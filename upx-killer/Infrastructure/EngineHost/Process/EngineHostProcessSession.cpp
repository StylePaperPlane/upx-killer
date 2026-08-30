#include "pch.h"
#include "Infrastructure/EngineHost/Process/EngineHostProcessSession.h"

#include "Infrastructure/EngineHost/Pipes/EngineHostPipeTransport.h"

#include <Windows.h>

#include <array>
#include <stdexcept>
#include <variant>
#include <vector>

namespace {
using namespace upx_killer;

class UniqueHandle final {
 public:
  UniqueHandle() = default;
  explicit UniqueHandle(HANDLE value) noexcept : value_(value) {}
  ~UniqueHandle() { reset(); }
  UniqueHandle(UniqueHandle const&) = delete;
  UniqueHandle& operator=(UniqueHandle const&) = delete;
  UniqueHandle(UniqueHandle&& other) noexcept : value_(other.release()) {}
  UniqueHandle& operator=(UniqueHandle&& other) noexcept {
    if (this != &other) reset(other.release());
    return *this;
  }
  [[nodiscard]] HANDLE get() const noexcept { return value_; }
  [[nodiscard]] HANDLE release() noexcept {
    auto value = value_;
    value_ = nullptr;
    return value;
  }
  void reset(HANDLE value = nullptr) noexcept {
    if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }
  explicit operator bool() const noexcept {
    return value_ && value_ != INVALID_HANDLE_VALUE;
  }

 private:
  HANDLE value_{};
};

class AttributeList final {
 public:
  AttributeList() {
    SIZE_T size{};
    InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    storage_.resize(size);
    list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
    if (!InitializeProcThreadAttributeList(list_, 1, 0, &size)) {
      throw std::runtime_error("attribute list");
    }
  }
  ~AttributeList() {
    if (list_) DeleteProcThreadAttributeList(list_);
  }
  [[nodiscard]] LPPROC_THREAD_ATTRIBUTE_LIST get() const noexcept { return list_; }

 private:
  std::vector<std::byte> storage_;
  LPPROC_THREAD_ATTRIBUTE_LIST list_{};
};

struct HostChannel {
  UniqueHandle process;
  UniqueHandle request;
  UniqueHandle response;
  std::uint32_t nativeCode{};

  [[nodiscard]] bool valid() const noexcept {
    return process && request && response;
  }
};

HostChannel LaunchHost(std::filesystem::path const& hostPath) {
  HostChannel channel{};
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE requestReadRaw{}, requestWriteRaw{};
  if (!CreatePipe(&requestReadRaw, &requestWriteRaw, &security, 0)) {
    channel.nativeCode = GetLastError();
    return channel;
  }
  UniqueHandle requestRead{requestReadRaw}, requestWrite{requestWriteRaw};
  HANDLE resultReadRaw{}, resultWriteRaw{};
  if (!CreatePipe(&resultReadRaw, &resultWriteRaw, &security, 0)) {
    channel.nativeCode = GetLastError();
    return channel;
  }
  UniqueHandle resultRead{resultReadRaw}, resultWrite{resultWriteRaw};
  if (!SetHandleInformation(requestWrite.get(), HANDLE_FLAG_INHERIT, 0) ||
      !SetHandleInformation(resultRead.get(), HANDLE_FLAG_INHERIT, 0)) {
    channel.nativeCode = GetLastError();
    return channel;
  }

  UniqueHandle nullOutput{CreateFileW(
      L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security,
      OPEN_EXISTING, 0, nullptr)};
  if (!nullOutput) {
    channel.nativeCode = GetLastError();
    return channel;
  }
  std::array<HANDLE, 3> inherited{
      requestRead.get(), resultWrite.get(), nullOutput.get()};
  AttributeList attributes;
  if (!UpdateProcThreadAttribute(
          attributes.get(), 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
          inherited.data(), sizeof(inherited), nullptr, nullptr)) {
    channel.nativeCode = GetLastError();
    return channel;
  }

  STARTUPINFOEXW startup{};
  startup.StartupInfo.cb = sizeof(startup);
  startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput = requestRead.get();
  startup.StartupInfo.hStdOutput = resultWrite.get();
  startup.StartupInfo.hStdError = nullOutput.get();
  startup.lpAttributeList = attributes.get();
  PROCESS_INFORMATION processInformation{};
  auto commandLine = L"\"" + hostPath.wstring() + L"\"";
  if (!CreateProcessW(
          hostPath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
          EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW |
              CREATE_UNICODE_ENVIRONMENT,
          nullptr, hostPath.parent_path().c_str(), &startup.StartupInfo,
          &processInformation)) {
    channel.nativeCode = GetLastError();
    return channel;
  }

  channel.process.reset(processInformation.hProcess);
  UniqueHandle thread{processInformation.hThread};
  requestRead.reset();
  resultWrite.reset();
  nullOutput.reset();
  channel.request = std::move(requestWrite);
  channel.response = std::move(resultRead);
  return channel;
}

contracts::JobResult ClientFailure(std::string detailCode,
                                   std::uint32_t nativeCode = 0) {
  return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Protocol,
          std::move(detailCode), std::nullopt, nativeCode};
}

void FinishHost(HostChannel& channel, DWORD timeout) noexcept {
  if (WaitForSingleObject(channel.process.get(), timeout) == WAIT_TIMEOUT) {
    TerminateProcess(channel.process.get(), WAIT_TIMEOUT);
    WaitForSingleObject(channel.process.get(), 5000);
  }
}
}

namespace upx_killer::infrastructure {
EngineHostCapabilityResult EngineHostProcessSession::QueryCapabilities(
    std::filesystem::path const& hostPath) noexcept {
  try {
    if (!std::filesystem::is_regular_file(hostPath)) {
      return {false, {}, "host.executable.not_found", ERROR_FILE_NOT_FOUND};
    }
    auto channel = LaunchHost(hostPath);
    if (!channel.valid()) {
      return {false, {}, "host.launch_failed", channel.nativeCode};
    }
    EngineHostPipeTransport transport{channel.response.get(), channel.request.get()};
    if (!transport.Write(contracts::protocol::QueryCapabilitiesMessage{})) {
      TerminateProcess(channel.process.get(), ERROR_WRITE_FAULT);
      return {false, {}, "host.protocol.write_failed", GetLastError()};
    }
    channel.request.reset();
    auto response = transport.Read();
    if (!response) {
      TerminateProcess(channel.process.get(), ERROR_READ_FAULT);
      return {false, {}, "host.protocol.read_failed", GetLastError()};
    }
    auto const* capabilities =
        std::get_if<contracts::protocol::CapabilitiesMessage>(&*response);
    if (!capabilities) {
      TerminateProcess(channel.process.get(), ERROR_INVALID_DATA);
      return {false, {}, "host.protocol.unexpected_message", ERROR_INVALID_DATA};
    }
    auto manifests = capabilities->manifests;
    FinishHost(channel, 5000);
    return {true, std::move(manifests), {}};
  } catch (...) {
    return {false, {}, "host.launch_failed"};
  }
}

contracts::JobResult EngineHostProcessSession::Execute(
    std::filesystem::path const& hostPath,
    contracts::UnpackJobRequest const& request,
    contracts::ProgressCallback const& progress) noexcept {
  try {
    if (!std::filesystem::is_regular_file(hostPath)) {
      return ClientFailure("host.executable.not_found", ERROR_FILE_NOT_FOUND);
    }
    if (request.outputPath.empty()) {
      return ClientFailure("host.output_path.required", ERROR_INVALID_PARAMETER);
    }
    auto channel = LaunchHost(hostPath);
    if (!channel.valid()) {
      return ClientFailure("host.launch_failed", channel.nativeCode);
    }
    EngineHostPipeTransport transport{channel.response.get(), channel.request.get()};
    if (!transport.Write(contracts::protocol::ExecuteJobMessage{request})) {
      TerminateProcess(channel.process.get(), ERROR_WRITE_FAULT);
      return ClientFailure("host.protocol.write_failed", GetLastError());
    }
    channel.request.reset();

    for (;;) {
      auto response = transport.Read();
      if (!response) {
        TerminateProcess(channel.process.get(), ERROR_READ_FAULT);
        return ClientFailure("host.protocol.read_failed", GetLastError());
      }
      if (auto const* message =
              std::get_if<contracts::protocol::ProgressMessage>(&*response)) {
        if (progress) progress(message->event);
        continue;
      }
      if (auto* message =
              std::get_if<contracts::protocol::ResultMessage>(&*response)) {
        auto result = std::move(message->result);
        FinishHost(channel, 5000);
        return result;
      }
      TerminateProcess(channel.process.get(), ERROR_INVALID_DATA);
      return ClientFailure("host.protocol.unexpected_message", ERROR_INVALID_DATA);
    }
  } catch (...) {
    return ClientFailure("host.launch_failed");
  }
}
}
