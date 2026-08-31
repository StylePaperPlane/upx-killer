#include "Infrastructure/Windows/WSL/Hosting/WslHostProcessSession.h"

#include "Infrastructure/Windows/Pipes/EngineHostPipeTransport.h"

namespace {
void CloseIfValid(HANDLE handle) noexcept {
  if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
}
}

namespace upx_killer::engine_host::wsl {
WslHostProcessSession::~WslHostProcessSession() {
  CloseIfValid(inputWrite_);
  CloseIfValid(outputRead_);
  if (process_) {
    if (WaitForSingleObject(process_, 0) == WAIT_TIMEOUT)
      TerminateProcess(process_, ERROR_CANCELLED);
    (void)WaitForSingleObject(process_, 3000);
    CloseHandle(process_);
  }
}

WslSessionStartResult WslHostProcessSession::Start(
    WslApi const& api, std::wstring_view distribution,
    std::wstring_view command) noexcept {
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
  HANDLE childInput{}, parentInput{}, parentOutput{}, childOutput{};
  if (!CreatePipe(&childInput, &parentInput, &attributes, 0) ||
      !SetHandleInformation(parentInput, HANDLE_FLAG_INHERIT, 0) ||
      !CreatePipe(&parentOutput, &childOutput, &attributes, 0) ||
      !SetHandleInformation(parentOutput, HANDLE_FLAG_INHERIT, 0)) {
    auto const error = GetLastError();
    CloseIfValid(childInput);
    CloseIfValid(parentInput);
    CloseIfValid(parentOutput);
    CloseIfValid(childOutput);
    return {nullptr, error};
  }
  auto nullHandle = CreateFileW(L"NUL", GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &attributes, OPEN_EXISTING, 0, nullptr);
  auto launched = api.Launch(distribution, command, childInput, childOutput,
                             nullHandle);
  CloseIfValid(childInput);
  CloseIfValid(childOutput);
  CloseIfValid(nullHandle);
  if (!launched.process) {
    CloseIfValid(parentInput);
    CloseIfValid(parentOutput);
    return {nullptr, launched.nativeCode};
  }
  return {std::unique_ptr<WslHostProcessSession>{
              new WslHostProcessSession{launched.process, parentInput,
                                        parentOutput}},
          0};
}

bool WslHostProcessSession::Write(
    contracts::protocol::EngineHostMessage const& message) const noexcept {
  EngineHostPipeTransport transport{outputRead_, inputWrite_};
  return transport.Write(message);
}

std::optional<contracts::protocol::EngineHostMessage>
WslHostProcessSession::Read() const noexcept {
  EngineHostPipeTransport transport{outputRead_, inputWrite_};
  return transport.Read();
}
}  // namespace upx_killer::engine_host::wsl
