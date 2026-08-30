#include "Tests/Support/EngineHostTestClient.h"

#include "Protocol/EngineHost/EngineHostProtocol.h"

#include <Windows.h>

namespace upx_killer::engine::tests {
HostExecutionResult ExecuteThroughEngineHost(std::filesystem::path const& hostPath,
                                             UnpackRequest const& request) noexcept {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE requestRead{}, requestWrite{}, resultRead{}, resultWrite{};
  if (!CreatePipe(&requestRead, &requestWrite, &security, 0) ||
      !CreatePipe(&resultRead, &resultWrite, &security, 0))
    return {};
  SetHandleInformation(requestWrite, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation(resultRead, HANDLE_FLAG_INHERIT, 0);

  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = requestRead;
  startup.hStdOutput = resultWrite;
  startup.hStdError = resultWrite;
  PROCESS_INFORMATION process{};
  auto commandLine = L"\"" + hostPath.wstring() + L"\"";
  auto const created = CreateProcessW(hostPath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
                                      CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, nullptr,
                                      hostPath.parent_path().c_str(), &startup, &process);
  CloseHandle(requestRead);
  CloseHandle(resultWrite);
  if (!created) {
    CloseHandle(requestWrite);
    CloseHandle(resultRead);
    return {};
  }

  auto const wrote = protocol::WriteRequest(requestWrite, request);
  CloseHandle(requestWrite);
  EngineResult result{};
  bool read{};
  for (;;) {
    protocol::HostResponse response{};
    if (!protocol::ReadResponse(resultRead, response)) break;
    if (response.result) {
      result = std::move(*response.result);
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
