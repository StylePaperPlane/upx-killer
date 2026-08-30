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

contracts::UnpackJobRequest ToJob(engine::UnpackRequest const& request) {
  contracts::UnpackJobRequest job{};
  job.targetPath = request.targetPath;
  job.outputPath = request.outputPath;
  job.timeoutMilliseconds = request.timeoutMilliseconds;
  job.maximumImageSize = request.maximumImageSize;
  job.retainFailedOutput = request.retainFailedOutput;
  if (request.oep)
    job.entryPoint = contracts::EntryPointHint{
        contracts::EntryPointAddressKind::RelativeVirtualAddress,
        request.oep->value};
  return job;
}

engine::EngineError MapError(std::string const& detail) {
  if (detail == "pe.target.invalid") return engine::EngineError::InvalidPe;
  if (detail == "pe.packer.unsupported") return engine::EngineError::UnsupportedPacker;
  if (detail == "pe.oep.not_found") return engine::EngineError::OepNotFound;
  if (detail == "pe.imports.not_found") return engine::EngineError::ImportsNotFound;
  if (detail == "pe.imports.ambiguous") return engine::EngineError::ImportsAmbiguous;
  if (detail == "artifact.write_failed") return engine::EngineError::OutputWriteFailed;
  if (detail == "artifact.validation_failed") return engine::EngineError::OutputValidationFailed;
  if (detail == "job.cancelled") return engine::EngineError::Cancelled;
  if (detail == "job.timed_out") return engine::EngineError::TimedOut;
  return detail.empty() ? engine::EngineError::None : engine::EngineError::RebuildFailed;
}

engine::EngineResult FromJob(contracts::JobResult result) {
  engine::EngineResult mapped{};
  switch (result.outcome) {
    case contracts::JobOutcome::Completed: mapped.outcome = engine::EngineOutcome::Completed; break;
    case contracts::JobOutcome::Partial: mapped.outcome = engine::EngineOutcome::Partial; break;
    case contracts::JobOutcome::UnsupportedTarget:
      mapped.outcome = engine::EngineOutcome::UnsupportedTarget; break;
    case contracts::JobOutcome::Cancelled: mapped.outcome = engine::EngineOutcome::Cancelled; break;
    case contracts::JobOutcome::TimedOut: mapped.outcome = engine::EngineOutcome::TimedOut; break;
    case contracts::JobOutcome::Failed: mapped.outcome = engine::EngineOutcome::Failed; break;
  }
  mapped.error = MapError(result.detailCode);
  mapped.nativeError = result.nativeCode;
  if (result.artifact) {
    mapped.artifact = engine::EngineArtifact{
        std::move(result.artifact->path),
        result.artifact->quality == contracts::ArtifactQuality::Complete
            ? engine::ArtifactQuality::Complete
            : engine::ArtifactQuality::Partial,
        result.artifact->loaderVerified,
        std::move(result.artifact->warnings)};
  }
  return mapped;
}
}

namespace upx_killer::engine::tests {
HostExecutionResult ExecuteThroughEngineHost(std::filesystem::path const& hostPath,
                                             UnpackRequest const& request) noexcept {
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
      contracts::protocol::ExecuteJobMessage{ToJob(request)});
  auto const wrote = frame && WriteExact(requestWrite, *frame);
  CloseHandle(requestWrite);
  EngineResult result{};
  bool read{};
  for (;;) {
    auto message = ReadMessage(resultRead);
    if (!message) break;
    if (auto* completed =
            std::get_if<contracts::protocol::ResultMessage>(&*message)) {
      result = FromJob(std::move(completed->result));
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
