#include "Infrastructure/Linux/Debugging/PtraceElfSnapshotCapture.h"

#include "Infrastructure/Linux/Debugging/Breakpoints/LinuxExecutionBreakpoint.h"
#include "Infrastructure/Linux/Debugging/Process/LinuxTracedProcess.h"
#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.h"

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <optional>
#include <thread>

namespace {
using namespace upx_killer;
using namespace upx_killer::elf_host::debugging;

engine::application::elf_capture::ElfCaptureResult Failure(
    contracts::JobOutcome outcome, contracts::ErrorCategory category,
    std::string code, std::uint32_t native = 0) {
  return {std::nullopt, 0,
          {outcome, category, std::move(code), std::nullopt, native}};
}

engine::application::elf_capture::ElfCaptureResult LaunchFailure(
    LinuxTraceLaunchResult const& launch) {
  auto code = "elf.capture.exec_failed";
  if (launch.error == LinuxTraceLaunchError::Fork)
    code = "elf.capture.fork_failed";
  else if (launch.error == LinuxTraceLaunchError::Ptrace)
    code = "elf.capture.ptrace_failed";
  return Failure(contracts::JobOutcome::Failed,
                 contracts::ErrorCategory::Execution, code,
                 launch.nativeCode);
}

bool Continue(pid_t pid, enum __ptrace_request request,
              int signal = 0) noexcept {
  return ptrace(request, pid, nullptr,
                reinterpret_cast<void*>(static_cast<intptr_t>(signal))) == 0;
}

bool RequiresDynamicLinkerPreEntryCapture(
    engine::elf::ElfImageLayout const& layout) {
  return std::any_of(layout.programHeaders.begin(), layout.programHeaders.end(),
                     [](auto const& header) { return header.type == 3; });
}

}  // namespace

namespace upx_killer::elf_host::debugging {
engine::application::elf_capture::ElfCaptureResult
PtraceElfSnapshotCapture::Capture(
    engine::application::elf_capture::ElfCaptureRequest const& request,
    std::stop_token stopToken) const noexcept {
  try {
    auto launch = LinuxTraceLauncher::Launch(
        request.target.sourcePath, request.target.dependencyDirectory);
    if (!launch.process) return LaunchFailure(launch);
    auto const pid = launch.process->Id();
    auto const deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(request.timeoutMilliseconds);
    bool enteringSyscall{true};
    std::optional<RecoveredElfImage> recovered;
    std::optional<engine::elf::CapturedElfImage> preEntryCapture;
    std::optional<LinuxExecutionBreakpoint> breakpoint;
    std::uint64_t resolvedEntry{};
    int status{};

    for (;;) {
      if (stopToken.stop_requested())
        return Failure(contracts::JobOutcome::Cancelled,
                       contracts::ErrorCategory::Cancelled, "job.cancelled");
      if (std::chrono::steady_clock::now() >= deadline)
        return Failure(contracts::JobOutcome::TimedOut,
                       contracts::ErrorCategory::TimedOut, "job.timed_out");
      auto const waited = waitpid(pid, &status, WNOHANG);
      if (waited == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }
      if (waited < 0) {
        if (errno == EINTR) continue;
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "elf.capture.wait_failed", errno);
      }
      if (WIFEXITED(status) || WIFSIGNALED(status))
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "elf.oep.not_found",
                       WIFEXITED(status) ? WEXITSTATUS(status)
                                         : 128u + WTERMSIG(status));
      if (!WIFSTOPPED(status)) continue;
      auto const signal = WSTOPSIG(status);

      if (breakpoint) {
        auto const restore = breakpoint->RestoreIfHit(
            pid, signal, request.target.packedLayout.imageClass);
        if (restore == BreakpointRestoreResult::Restored) {
          if (!recovered)
            return Failure(contracts::JobOutcome::Failed,
                           contracts::ErrorCategory::Internal,
                           "elf.capture.state_invalid");
          std::optional<engine::elf::CapturedElfImage> captured;
          if (RequiresDynamicLinkerPreEntryCapture(recovered->layout)) {
            captured = std::move(preEntryCapture);
          } else {
            captured = RecoveredElfImageLocator::Capture(
                pid, *recovered, request.maximumImageSize);
          }
          if (!captured)
            return Failure(contracts::JobOutcome::Failed,
                           contracts::ErrorCategory::Execution,
                           "elf.capture.read_failed", errno);
          return {std::move(captured), resolvedEntry, {}};
        }
        if (restore == BreakpointRestoreResult::Failed)
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Execution,
                         "elf.oep.breakpoint_restore_failed", errno);
        if (!Continue(pid, PTRACE_CONT, signal == SIGTRAP ? 0 : signal))
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Execution,
                         "elf.capture.continue_failed", errno);
        continue;
      }

      if (signal == (SIGTRAP | 0x80)) {
        if (!enteringSyscall) {
          if (!recovered)
            recovered = RecoveredElfImageLocator::Find(
                pid, request.target.packedLayout);
        } else if (recovered &&
                   RecoveredElfImageLocator::AllSegmentsReady(pid,
                                                              *recovered)) {
          if (RequiresDynamicLinkerPreEntryCapture(recovered->layout)) {
            preEntryCapture = RecoveredElfImageLocator::Capture(
                pid, *recovered, request.maximumImageSize);
            if (!preEntryCapture)
              return Failure(contracts::JobOutcome::Failed,
                             contracts::ErrorCategory::Execution,
                             "elf.capture.read_failed", errno);
            if (!RecoveredElfImageLocator::HasCompleteDynamicLinkage(
                    *preEntryCapture)) {
              preEntryCapture.reset();
              enteringSyscall = !enteringSyscall;
              if (!Continue(pid, PTRACE_SYSCALL))
                return Failure(contracts::JobOutcome::Failed,
                               contracts::ErrorCategory::Execution,
                               "elf.capture.continue_failed", errno);
              continue;
            }
          }
          auto const relativeEntry = recovered->layout.entryPoint;
          if (request.target.explicitEntryPoint &&
              request.target.explicitEntryPoint->value != relativeEntry)
            return Failure(contracts::JobOutcome::Failed,
                           contracts::ErrorCategory::Execution,
                           "elf.oep.explicit_mismatch");
          resolvedEntry = recovered->loadBias + relativeEntry;
          breakpoint = LinuxExecutionBreakpoint::Install(pid, resolvedEntry);
          if (!breakpoint) {
            return Failure(contracts::JobOutcome::Failed,
                           contracts::ErrorCategory::Execution,
                           "elf.oep.breakpoint_failed", errno);
          }
        }
        enteringSyscall = !enteringSyscall;
        if (!Continue(pid, breakpoint ? PTRACE_CONT : PTRACE_SYSCALL))
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Execution,
                         "elf.capture.continue_failed", errno);
        continue;
      }
      if (!Continue(pid, PTRACE_SYSCALL, signal == SIGTRAP ? 0 : signal))
        return Failure(contracts::JobOutcome::Failed,
                       contracts::ErrorCategory::Execution,
                       "elf.capture.continue_failed", errno);
    }
  } catch (...) {
    return Failure(contracts::JobOutcome::Failed,
                   contracts::ErrorCategory::Internal,
                   "elf.capture.unhandled_exception");
  }
}
}  // namespace upx_killer::elf_host::debugging
