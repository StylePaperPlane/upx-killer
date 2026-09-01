#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"

#include "Infrastructure/Windows/Debugging/DebugProcess.h"
#include "Infrastructure/Windows/Debugging/ProcessMemoryReader.h"
#include "Infrastructure/Windows/Debugging/SoftwareBreakpointSet.h"
#include "Infrastructure/Windows/Debugging/RemoteModuleCatalog.h"
#include "Infrastructure/Windows/Debugging/Loading/DebugTargetLoader.h"
#include "Infrastructure/Windows/Debugging/Staging/StagedDebugTarget.h"
#include "Infrastructure/Windows/Debugging/ThreadContext/ThreadContextController.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::debugging;

constexpr std::uint32_t ExplicitBreakpointId = 0;
constexpr std::uint32_t PackedEntryBreakpointId = 1;
constexpr std::uint32_t CandidateBreakpointBase = 2;
constexpr std::size_t ValidationByteCount = 16;
constexpr DWORD StatusWx86Breakpoint = 0x4000001f;

bool IsBreakpointException(DWORD exceptionCode) noexcept {
  return exceptionCode == EXCEPTION_BREAKPOINT || exceptionCode == StatusWx86Breakpoint;
}

void CloseDebugEventHandles(DEBUG_EVENT const& event) noexcept {
  if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
    if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
    if (event.u.CreateProcessInfo.hThread) CloseHandle(event.u.CreateProcessInfo.hThread);
    if (event.u.CreateProcessInfo.hProcess) CloseHandle(event.u.CreateProcessInfo.hProcess);
  } else if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && event.u.CreateThread.hThread) {
    CloseHandle(event.u.CreateThread.hThread);
  } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile) {
    CloseHandle(event.u.LoadDll.hFile);
  }
}

bool ReadValidationBytes(HANDLE process, std::uint64_t address,
                         std::array<std::byte, ValidationByteCount>& bytes) noexcept {
  SIZE_T read{};
  return ReadProcessMemory(process, reinterpret_cast<void const*>(address), bytes.data(),
                           bytes.size(), &read) &&
         read == bytes.size();
}

bool HasMeaningfulChange(std::array<std::byte, ValidationByteCount> const& before,
                         std::array<std::byte, ValidationByteCount> const& after) noexcept {
  if (before == after) return false;
  auto const allZero =
      std::all_of(after.begin(), after.end(), [](std::byte value) { return value == std::byte{}; });
  auto const allTrap = std::all_of(after.begin(), after.end(),
                                   [](std::byte value) { return value == std::byte{0xcc}; });
  return !allZero && !allTrap;
}

void DrainDebuggeeExit(DWORD processId) noexcept {
  auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
  while (std::chrono::steady_clock::now() < deadline) {
    DEBUG_EVENT event{};
    if (!WaitForDebugEvent(&event, 50)) {
      if (GetLastError() == ERROR_SEM_TIMEOUT) continue;
      return;
    }
    auto const isTargetExit =
        event.dwProcessId == processId && event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT;
    CloseDebugEventHandles(event);
    (void)ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    if (isTargetExit) return;
  }
}

DebugSessionError MapThreadContextError(
    thread_context::ThreadContextError error) noexcept {
  using thread_context::ThreadContextError;
  switch (error) {
    case ThreadContextError::None: return DebugSessionError::None;
    case ThreadContextError::MachineMismatch:
      return DebugSessionError::MachineMismatch;
    case ThreadContextError::Wow64Unavailable:
      return DebugSessionError::Wow64Unavailable;
    case ThreadContextError::PlatformCallFailed:
      return DebugSessionError::ProtocolFailure;
  }
  return DebugSessionError::ProtocolFailure;
}
}

namespace upx_killer::engine::debugging {
DebugCaptureResult WindowsDebugSession::Capture(DebugLaunchRequest const& request,
                                                CaptureCallback const& capture,
                                                std::stop_token stopToken) noexcept {
#if !defined(_M_X64)
  (void)request;
  (void)capture;
  (void)stopToken;
  return {DebugSessionError::UnsupportedHost, ERROR_NOT_SUPPORTED};
#else
  if (!capture || request.sizeOfImage == 0)
    return {DebugSessionError::InvalidRequest, ERROR_INVALID_PARAMETER};

  auto const* explicitOep = std::get_if<RelativeVirtualAddress>(&request.oepTarget);
  auto const* discovery = std::get_if<pe::oep::OepDiscoveryPlan>(&request.oepTarget);
  if ((explicitOep && (explicitOep->value >= request.sizeOfImage ||
                       (request.imageKind == pe::PeImageKind::DynamicLibrary &&
                        explicitOep->value == 0))) ||
      (discovery && discovery->candidates.empty()))
    return {explicitOep ? DebugSessionError::InvalidRequest
                        : DebugSessionError::EntryPointNotFound,
            ERROR_INVALID_PARAMETER};

  std::uint32_t launchError{};
  std::optional<staging::StagedDebugTarget> stagedTarget;
  auto launchPath = request.targetPath;
  if (!request.stagedTargetImage.empty()) {
    stagedTarget = staging::StagedDebugTarget::Create(request.targetPath, request.imageKind,
                                                       request.stagedTargetImage,
                                                       launchError);
    if (!stagedTarget) return {DebugSessionError::ControlledBaseUnavailable, launchError};
    launchPath = stagedTarget->ImagePath();
  }
  auto const workingDirectory = request.workingDirectory.empty()
                                    ? request.targetPath.parent_path()
                                    : request.workingDirectory;
  auto launch = loading::DebugTargetLoader::CreateCommand(
      request.imageKind, launchPath, workingDirectory, request.dllLoader,
      launchError);
  if (!launch) return {DebugSessionError::TargetLibraryLaunchFailed, launchError};
  auto process = DebugProcess::Launch(launch->application, std::move(launch->commandLine),
                                      workingDirectory, launchError);
  if (!process) return {DebugSessionError::ProcessLaunchFailed, launchError};

  SoftwareBreakpointSet breakpoints{process->ProcessHandle()};
  auto const started = std::chrono::steady_clock::now();
  std::uint64_t imageBase{};
  DWORD entryThreadId{};
  std::uint64_t entryStackPointer{};
  bool processAttachValidated{request.imageKind == pe::PeImageKind::Executable};
  std::vector<std::array<std::byte, ValidationByteCount> > baselines;
  if (discovery) baselines.resize(discovery->candidates.size());

  for (;;) {
    if (stopToken.stop_requested()) {
      process->Terminate(ERROR_CANCELLED);
      DrainDebuggeeExit(process->ProcessId());
      return {DebugSessionError::Cancelled, ERROR_CANCELLED};
    }
    if (std::chrono::steady_clock::now() - started >= request.timeout) {
      process->Terminate(WAIT_TIMEOUT);
      DrainDebuggeeExit(process->ProcessId());
      return {DebugSessionError::TimedOut, WAIT_TIMEOUT};
    }

    DEBUG_EVENT event{};
    if (!WaitForDebugEvent(&event, 50)) {
      auto const error = GetLastError();
      if (error == ERROR_SEM_TIMEOUT) continue;
      process->Terminate(error);
      DrainDebuggeeExit(process->ProcessId());
      return {DebugSessionError::ProtocolFailure, error};
    }

    DWORD continueStatus = DBG_CONTINUE;
    DebugSessionError terminalError = DebugSessionError::None;
    std::uint32_t terminalNativeError{};
    bool terminal{};
    bool terminalEventIsExit{};

    if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
      auto const formatError = thread_context::ThreadContextController::ValidateProcess(
          process->ProcessHandle(), request.format, terminalNativeError);
      if (formatError != thread_context::ThreadContextError::None) {
        terminal = true;
        terminalError = MapThreadContextError(formatError);
      } else if (!launch->targetArrivesAsDll) {
        imageBase = reinterpret_cast<std::uint64_t>(event.u.CreateProcessInfo.lpBaseOfImage);
        if (request.requiredImageBase && imageBase != request.requiredImageBase->value) {
          terminal = true;
          terminalError = DebugSessionError::ControlledBaseUnavailable;
          terminalNativeError = ERROR_INVALID_ADDRESS;
        }
      }
      if (!terminal && !launch->targetArrivesAsDll) {
        std::uint32_t breakpointError{};
        auto const address =
            imageBase + (explicitOep ? explicitOep->value : discovery->packedEntryPoint.value);
        auto const id = explicitOep ? ExplicitBreakpointId : PackedEntryBreakpointId;
        if (!breakpoints.Install(address, id, breakpointError)) {
          terminal = true;
          terminalError = DebugSessionError::ProtocolFailure;
          terminalNativeError = breakpointError;
        }
      }
    } else if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT &&
               launch->targetArrivesAsDll && imageBase == 0 &&
               loading::DebugTargetLoader::IsTargetDllEvent(event.u.LoadDll.hFile, launchPath)) {
      imageBase = reinterpret_cast<std::uint64_t>(event.u.LoadDll.lpBaseOfDll);
      if (request.requiredImageBase && imageBase != request.requiredImageBase->value) {
        terminal = true;
        terminalError = DebugSessionError::ControlledBaseUnavailable;
        terminalNativeError = ERROR_INVALID_ADDRESS;
      } else {
        std::uint32_t breakpointError{};
        auto const address =
            imageBase + (explicitOep ? explicitOep->value : discovery->packedEntryPoint.value);
        auto const id = explicitOep ? ExplicitBreakpointId : PackedEntryBreakpointId;
        if (!breakpoints.Install(address, id, breakpointError)) {
          terminal = true;
          terminalError = DebugSessionError::ProtocolFailure;
          terminalNativeError = breakpointError;
        }
      }
    } else if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
      auto const& exception = event.u.Exception.ExceptionRecord;
      auto const exceptionAddress = reinterpret_cast<std::uint64_t>(exception.ExceptionAddress);
      auto const breakpointId = IsBreakpointException(exception.ExceptionCode)
                                    ? breakpoints.Find(exceptionAddress)
                                    : std::nullopt;
      if (breakpointId) {
        std::uint32_t contextError{};
        auto context = thread_context::ThreadContextController::Open(
            event.dwThreadId, request.format, contextError);
        if (!context ||
            !breakpoints.Restore(exceptionAddress, contextError)) {
          terminal = true;
          terminalError = DebugSessionError::ProtocolFailure;
          terminalNativeError = contextError;
        } else if (!context->SetInstructionPointer(exceptionAddress, contextError)) {
          terminal = true;
          terminalError = DebugSessionError::ProtocolFailure;
          terminalNativeError = contextError;
        } else {
          if (*breakpointId == ExplicitBreakpointId) {
            if (request.imageKind == pe::PeImageKind::DynamicLibrary) {
              auto const invocation = context->ReadDllEntryInvocation(
                  process->ProcessHandle(), contextError);
              processAttachValidated = invocation && invocation->reason == DLL_PROCESS_ATTACH;
            }
            if (!processAttachValidated) {
              terminal = true;
              terminalError = DebugSessionError::TargetLibraryAttachInvalid;
            }
            if (!context->Commit(contextError)) {
              terminalError = DebugSessionError::ProtocolFailure;
              terminalNativeError = contextError;
            } else {
              ProcessMemoryReader reader{process->ProcessHandle()};
              pe::imports::RuntimeModuleSnapshot runtime{};
              if (request.collectRuntimeImports) {
                auto catalog =
                    RemoteModuleCatalog::Capture(process->ProcessHandle(), process->ProcessId(),
                                                 request.format, LoadedAddress{imageBase});
                if (!catalog.Succeeded()) {
                  terminal = true;
                  terminalError = DebugSessionError::ImportSnapshotFailed;
                  terminalNativeError = catalog.nativeError;
                } else
                  runtime = std::move(catalog.snapshot);
              }
              if (!terminal &&
                  !capture(reader, {{imageBase}, request.sizeOfImage},
                           *explicitOep, runtime))
                terminalError = DebugSessionError::CaptureRejected;
            }
            terminal = true;
          } else if (*breakpointId == PackedEntryBreakpointId) {
            entryThreadId = event.dwThreadId;
            entryStackPointer = context->Context().stackPointer;
            if (request.imageKind == pe::PeImageKind::DynamicLibrary) {
              auto const invocation = context->ReadDllEntryInvocation(
                  process->ProcessHandle(), contextError);
              processAttachValidated = invocation && invocation->reason == DLL_PROCESS_ATTACH;
            }
            if (!context->Commit(contextError)) {
              terminal = true;
              terminalError = DebugSessionError::ProtocolFailure;
              terminalNativeError = contextError;
            } else {
              for (std::size_t index = 0; index < discovery->candidates.size(); ++index) {
                auto const& candidate = discovery->candidates[index];
                if (!ReadValidationBytes(process->ProcessHandle(),
                                         imageBase + candidate.validationTarget.value,
                                         baselines[index]) ||
                    !breakpoints.Install(
                        imageBase + candidate.transfer.value,
                        CandidateBreakpointBase + static_cast<std::uint32_t>(index),
                        terminalNativeError)) {
                  terminal = true;
                  terminalError = DebugSessionError::ProtocolFailure;
                  break;
                }
              }
            }
          } else {
            auto const index = static_cast<std::size_t>(*breakpointId - CandidateBreakpointBase);
            auto const& candidate = discovery->candidates[index];
            std::array<std::byte, ValidationByteCount> current{};
            auto const threadMatches = event.dwThreadId == entryThreadId;
            auto const stackMatches = context->Context().stackPointer == entryStackPointer;
            auto const targetReadable = ReadValidationBytes(
                process->ProcessHandle(), imageBase + candidate.validationTarget.value, current);
            auto const targetChanged = targetReadable && HasMeaningfulChange(baselines[index], current);
            auto const valid = threadMatches && stackMatches && processAttachValidated &&
                               targetReadable && targetChanged;
            if (!context->Commit(contextError)) {
              terminal = true;
              terminalError = DebugSessionError::ProtocolFailure;
              terminalNativeError = contextError;
            } else if (valid) {
              ProcessMemoryReader reader{process->ProcessHandle()};
              pe::imports::RuntimeModuleSnapshot runtime{};
              if (request.collectRuntimeImports) {
                auto catalog =
                    RemoteModuleCatalog::Capture(process->ProcessHandle(), process->ProcessId(),
                                                 request.format, LoadedAddress{imageBase});
                if (!catalog.Succeeded()) {
                  terminal = true;
                  terminalError = DebugSessionError::ImportSnapshotFailed;
                  terminalNativeError = catalog.nativeError;
                } else
                  runtime = std::move(catalog.snapshot);
              }
              if (!terminal &&
                  !capture(reader, {{imageBase}, request.sizeOfImage},
                           candidate.target, runtime))
                terminalError = DebugSessionError::CaptureRejected;
              terminal = true;
            } else if (breakpoints.Count() == 0) {
              terminal = true;
              terminalError = DebugSessionError::EntryPointNotFound;
            }
          }
        }
      } else if (!IsBreakpointException(exception.ExceptionCode)) {
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
      }
    } else if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
      terminal = true;
      terminalEventIsExit = true;
      terminalError = discovery ? DebugSessionError::EntryPointNotFound
                                : DebugSessionError::TargetExited;
      terminalNativeError = event.u.ExitProcess.dwExitCode;
    }

    CloseDebugEventHandles(event);
    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continueStatus) && !terminal)
      return {DebugSessionError::ProtocolFailure, GetLastError()};
    if (terminal) {
      if (!terminalEventIsExit) {
        process->Terminate(terminalNativeError);
        DrainDebuggeeExit(process->ProcessId());
      }
      return {terminalError, terminalNativeError, LoadedAddress{imageBase}};
    }
  }
#endif
}
}
