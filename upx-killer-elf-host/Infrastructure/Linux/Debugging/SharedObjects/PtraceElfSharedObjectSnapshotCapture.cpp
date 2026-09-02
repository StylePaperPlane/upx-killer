#include "Infrastructure/Linux/Debugging/SharedObjects/PtraceElfSharedObjectSnapshotCapture.h"

#include "Infrastructure/Linux/Debugging/Process/LinuxTracedProcess.h"
#include "Infrastructure/Linux/Debugging/Recovery/RecoveredElfImageLocator.h"
#include "Infrastructure/Linux/Debugging/SharedObjects/RecoveredSharedObjectLocator.h"
#include "Core/ELF/SharedObjects/UpxSharedObjectLayoutRecoverer.h"
#include "Core/ELF/SharedObjects/LoadedSharedObjectNormalizer.h"

#include <sys/ptrace.h>
#include <sys/wait.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <thread>

namespace {
using namespace upx_killer;

engine::application::elf_capture::ElfCaptureResult Failure(
    contracts::JobOutcome outcome, contracts::ErrorCategory category,
    std::string code, std::uint32_t native = 0) {
  return {std::nullopt, 0,
          {outcome, category, std::move(code), std::nullopt, native}};
}
}  // namespace

namespace upx_killer::elf_host::debugging {
engine::application::elf_capture::ElfCaptureResult
PtraceElfSharedObjectSnapshotCapture::Capture(
    engine::application::elf_capture::ElfCaptureRequest const& request,
    std::stop_token stopToken) const noexcept {
  try {
    if (request.target.explicitEntryPoint)
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::InvalidRequest,
                     "elf.shared_object.explicit_entry_unsupported");
    auto recoveredLayout =
        engine::elf::shared_objects::UpxSharedObjectLayoutRecoverer::Recover(
            request.target.sourceBytes, request.target.packedLayout);
    if (!recoveredLayout.layout)
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Execution,
                     std::move(recoveredLayout.detailCode));
    auto loader = loaders_.Resolve(request.target.packedLayout.imageClass);
    if (!loader)
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Configuration,
                     "elf.shared_object.loader_missing");
    auto launch = LinuxTraceLauncher::Launch(
        {*loader, request.target.dependencyDirectory,
         {request.target.sourcePath.string()}, LinuxTraceStartMode::Continue});
    if (!launch.process)
      return Failure(contracts::JobOutcome::Failed,
                     contracts::ErrorCategory::Execution,
                     "elf.shared_object.loader_launch_failed",
                     launch.nativeCode);
    auto const pid = launch.process->Id();
    auto const deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(request.timeoutMilliseconds);
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
                       "elf.shared_object.load_failed",
                       WIFEXITED(status) ? WEXITSTATUS(status)
                                         : 128u + WTERMSIG(status));
      if (!WIFSTOPPED(status)) continue;
      auto const signal = WSTOPSIG(status);
      if (signal == SIGSTOP) {
        auto recovered = RecoveredSharedObjectLocator::Find(
            pid, request.target.sourcePath, *recoveredLayout.layout);
        if (!recovered)
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Execution,
                         "elf.shared_object.recovery_failed");
        if (!RecoveredSharedObjectLocator::AllSegmentsReadable(pid,
                                                                *recovered))
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Execution,
                         "elf.shared_object.segments_not_ready");
        auto captured = RecoveredElfImageLocator::Capture(
            pid, *recovered, request.maximumImageSize);
        if (!captured ||
            !RecoveredElfImageLocator::HasCompleteDynamicLinkage(*captured))
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Execution,
                         "elf.capture.read_failed", errno);
        auto normalized =
            engine::elf::shared_objects::LoadedSharedObjectNormalizer::Normalize(
                *captured, request.target.packedLayout);
        if (!normalized.normalized)
          return Failure(contracts::JobOutcome::Failed,
                         contracts::ErrorCategory::Reconstruction,
                         std::move(normalized.detailCode));
        return {std::move(captured), 0, {}};
      }
      if (ptrace(PTRACE_CONT, pid, nullptr,
                 reinterpret_cast<void*>(static_cast<intptr_t>(
                     signal == SIGTRAP ? 0 : signal))) != 0)
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
