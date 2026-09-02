#include "Infrastructure/Windows/WSL/WslElfHostClient.h"

#include "Infrastructure/Windows/WSL/Hosting/WslHostProcessSession.h"

namespace {
upx_killer::contracts::JobResult Failure(
    upx_killer::contracts::ErrorCategory category, std::string code,
    std::uint32_t nativeCode = 0) {
  return {upx_killer::contracts::JobOutcome::Failed, category,
          std::move(code), std::nullopt, nativeCode};
}
}

namespace upx_killer::engine_host::wsl {
std::uint32_t WslElfHostClient::MakeExecutable(
    WslStagedJob const& staged) const noexcept {
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
  auto nullHandle = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &attributes, OPEN_EXISTING, 0, nullptr);
  if (nullHandle == INVALID_HANDLE_VALUE) return GetLastError();
  auto command = L"/bin/chmod 700 " +
                 std::wstring{staged.linuxHost.begin(), staged.linuxHost.end()} +
                 L" " +
                 std::wstring{staged.linuxLoader32.begin(), staged.linuxLoader32.end()} +
                 L" " +
                 std::wstring{staged.linuxLoader64.begin(), staged.linuxLoader64.end()} +
                 L" " +
                 std::wstring{staged.linuxTarget.begin(),
                              staged.linuxTarget.end()};
  auto launched = api_.Launch(distribution_, command, nullHandle, nullHandle,
                              nullHandle);
  CloseHandle(nullHandle);
  if (!launched.process) return launched.nativeCode;
  auto const wait = WaitForSingleObject(launched.process, 10'000);
  DWORD exitCode{};
  auto const queried = GetExitCodeProcess(launched.process, &exitCode);
  if (wait != WAIT_OBJECT_0) TerminateProcess(launched.process, ERROR_TIMEOUT);
  CloseHandle(launched.process);
  if (wait != WAIT_OBJECT_0)
    return wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
  return queried && exitCode == 0 ? 0u
                                 : (exitCode == 0 ? GetLastError() : exitCode);
}

contracts::JobResult WslElfHostClient::Execute(
    contracts::UnpackJobRequest const& request,
    contracts::ProgressCallback const& progress,
    std::stop_token stopToken) const noexcept {
  if (stopToken.stop_requested())
    return {contracts::JobOutcome::Cancelled,
            contracts::ErrorCategory::Cancelled, "job.cancelled",
            std::nullopt, 0};
  if (!api_.Available() || distribution_.empty())
    return Failure(contracts::ErrorCategory::Configuration,
                   "elf.wsl.not_configured", ERROR_NOT_SUPPORTED);
  auto staged = bridge_.Stage(distribution_, linuxHostSource_, request.targetPath);
  if (!staged.job)
    return Failure(contracts::ErrorCategory::Configuration,
                   std::move(staged.detailCode), staged.nativeCode);
  if (auto const error = MakeExecutable(*staged.job); error != 0)
    return Failure(contracts::ErrorCategory::Configuration,
                   "elf.wsl.chmod_failed", error);
  auto session = WslHostProcessSession::Start(
      api_, distribution_,
      std::wstring{staged.job->linuxHost.begin(), staged.job->linuxHost.end()});
  if (!session.session)
    return Failure(contracts::ErrorCategory::Execution,
                   "elf.wsl.host_launch_failed", session.nativeCode);
  auto remoteRequest = request;
  remoteRequest.targetPath = staged.job->linuxTarget;
  remoteRequest.outputPath = staged.job->linuxOutput;
  if (!session.session->Write(
          contracts::protocol::ExecuteJobMessage{remoteRequest}))
    return Failure(contracts::ErrorCategory::Protocol,
                   "elf.wsl.protocol_write_failed", GetLastError());
  for (;;) {
    auto message = session.session->Read(stopToken);
    if (!message && stopToken.stop_requested())
      return {contracts::JobOutcome::Cancelled,
              contracts::ErrorCategory::Cancelled, "job.cancelled",
              std::nullopt, ERROR_CANCELLED};
    if (!message)
      return Failure(contracts::ErrorCategory::Protocol,
                     "elf.wsl.protocol_read_failed", GetLastError());
    if (auto const* update =
            std::get_if<contracts::protocol::ProgressMessage>(&*message)) {
      if (progress) progress(update->event);
      continue;
    }
    auto* result =
        std::get_if<contracts::protocol::ResultMessage>(&*message);
    if (!result)
      return Failure(contracts::ErrorCategory::Protocol,
                     "elf.wsl.protocol_message_unexpected");
    if (!result->result.artifact) return std::move(result->result);
    auto const copyError = staged.job->CopyOutputTo(request.outputPath);
    if (copyError != 0)
      return Failure(contracts::ErrorCategory::Storage,
                     "elf.wsl.output_copy_failed", copyError);
    result->result.artifact->path = request.outputPath;
    return std::move(result->result);
  }
}
}  // namespace upx_killer::engine_host::wsl
