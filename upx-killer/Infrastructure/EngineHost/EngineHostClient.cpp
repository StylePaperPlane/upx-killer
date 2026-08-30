#include "pch.h"
#include "Infrastructure/EngineHost/EngineHostClient.h"

#include "Infrastructure/EngineHost/Pipes/EngineHostPipeTransport.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <stdexcept>
#include <variant>
#include <vector>

namespace {
using namespace upx_killer;

void CleanupStaleArtifacts(std::filesystem::path const& root) noexcept {
  try {
    if (!std::filesystem::is_directory(root)) return;
    auto const cutoff = std::filesystem::file_time_type::clock::now() -
                        std::chrono::hours{24 * 7};
    for (auto const& entry : std::filesystem::directory_iterator(root)) {
      std::error_code error;
      if (entry.is_directory(error) && !error &&
          entry.last_write_time(error) < cutoff && !error)
        std::filesystem::remove_all(entry.path(), error);
    }
  } catch (...) {
  }
}

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
    if (!InitializeProcThreadAttributeList(list_, 1, 0, &size))
      throw std::runtime_error("attribute list");
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

  UniqueHandle nullOutput{CreateFileW(L"NUL", GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr)};
  if (!nullOutput) {
    channel.nativeCode = GetLastError();
    return channel;
  }
  std::array<HANDLE, 3> inherited{requestRead.get(), resultWrite.get(), nullOutput.get()};
  AttributeList attributes;
  if (!UpdateProcThreadAttribute(attributes.get(), 0,
      PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited),
      nullptr, nullptr)) {
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
  if (!CreateProcessW(hostPath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
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
}

namespace upx_killer::infrastructure {
EngineHostClient::EngineHostClient(
    std::filesystem::path hostPath,
    std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore)
    : m_hostPath(std::move(hostPath)), m_settingsStore(std::move(settingsStore)) {}

std::filesystem::path EngineHostClient::AdjacentHostPath() {
  std::vector<wchar_t> buffer(32768);
  auto const length = GetModuleFileNameW(nullptr, buffer.data(),
                                         static_cast<DWORD>(buffer.size()));
  if (length == 0 || length == buffer.size()) return {};
  return std::filesystem::path{std::wstring_view{buffer.data(), length}}.parent_path() /
         L"upx_killer_engine_host.exe";
}

std::vector<contracts::BackendManifest> EngineHostClient::QueryCapabilities() noexcept {
  std::scoped_lock lock{m_capabilitiesMutex};
  if (m_capabilities) return *m_capabilities;
  try {
    if (!std::filesystem::is_regular_file(m_hostPath)) return {};
    auto channel = LaunchHost(m_hostPath);
    if (!channel.valid()) return {};
    EngineHostPipeTransport transport{channel.response.get(), channel.request.get()};
    if (!transport.Write(contracts::protocol::QueryCapabilitiesMessage{})) {
      TerminateProcess(channel.process.get(), ERROR_WRITE_FAULT);
      return {};
    }
    channel.request.reset();
    auto response = transport.Read();
    if (!response) {
      TerminateProcess(channel.process.get(), ERROR_READ_FAULT);
      return {};
    }
    auto capabilities = std::get_if<contracts::protocol::CapabilitiesMessage>(&*response);
    if (!capabilities) {
      TerminateProcess(channel.process.get(), ERROR_INVALID_DATA);
      return {};
    }
    if (WaitForSingleObject(channel.process.get(), 5'000) == WAIT_TIMEOUT)
      TerminateProcess(channel.process.get(), WAIT_TIMEOUT);
    m_capabilities = capabilities->manifests;
    return *m_capabilities;
  } catch (...) {
    return {};
  }
}

contracts::JobResult EngineHostClient::Execute(
    contracts::UnpackJobRequest const& request,
    ProgressCallback const& progress) noexcept {
  try {
    if (!std::filesystem::is_regular_file(m_hostPath))
      return ClientFailure("host.executable.not_found", ERROR_FILE_NOT_FOUND);
    if (!m_settingsStore) return ClientFailure("host.settings.unavailable");

    auto const settings = m_settingsStore->Load();
    if (settings.directory.empty()) return ClientFailure("host.temporary_directory.invalid");
    if (settings.deleteAfterExport) CleanupStaleArtifacts(settings.directory);

    auto hostRequest = request;
    hostRequest.retainFailedOutput = !settings.deleteAfterExport;
    if (hostRequest.outputPath.empty()) {
      auto const session = std::to_wstring(GetCurrentProcessId()) + L"-" +
                           std::to_wstring(GetTickCount64());
      auto extension = request.targetPath.extension().wstring();
      std::transform(extension.begin(), extension.end(), extension.begin(),
                     [](wchar_t value) {
                       return static_cast<wchar_t>(std::towlower(value));
                     });
      if (extension != L".dll") extension = L".exe";
      hostRequest.outputPath = settings.directory / session /
          (request.targetPath.stem().wstring() + L".dumped" + extension);
    }

    auto channel = LaunchHost(m_hostPath);
    if (!channel.valid()) return ClientFailure("host.launch_failed", channel.nativeCode);
    EngineHostPipeTransport transport{channel.response.get(), channel.request.get()};
    if (!transport.Write(contracts::protocol::ExecuteJobMessage{hostRequest})) {
      TerminateProcess(channel.process.get(), ERROR_WRITE_FAULT);
      return ClientFailure("host.protocol.write_failed", GetLastError());
    }
    channel.request.reset();

    contracts::JobResult result = ClientFailure("host.protocol.response_missing");
    for (;;) {
      auto response = transport.Read();
      if (!response) {
        TerminateProcess(channel.process.get(), ERROR_READ_FAULT);
        return ClientFailure("host.protocol.read_failed", GetLastError());
      }
      if (auto message = std::get_if<contracts::protocol::ProgressMessage>(&*response)) {
        if (progress) progress(message->event);
        continue;
      }
      if (auto message = std::get_if<contracts::protocol::ResultMessage>(&*response)) {
        result = std::move(message->result);
        break;
      }
      TerminateProcess(channel.process.get(), ERROR_INVALID_DATA);
      return ClientFailure("host.protocol.unexpected_message", ERROR_INVALID_DATA);
    }
    if (WaitForSingleObject(channel.process.get(), 5'000) == WAIT_TIMEOUT)
      TerminateProcess(channel.process.get(), WAIT_TIMEOUT);
    return result;
  } catch (...) {
    return ClientFailure("host.launch_failed");
  }
}
}
