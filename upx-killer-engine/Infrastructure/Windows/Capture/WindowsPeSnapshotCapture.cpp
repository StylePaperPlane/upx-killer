#include "Infrastructure/Windows/Capture/WindowsPeSnapshotCapture.h"

#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"

namespace upx_killer::engine::capture {
application::pe_capture::PeSnapshotCaptureResult WindowsPeSnapshotCapture::CaptureOne(
    application::pe_capture::PeSnapshotCaptureRequest const& request,
    std::function<void(EngineStage)> const& progress,
    std::stop_token stopToken) const noexcept {
  using application::pe_capture::PeCapturedRun;
  if (!request.layout) {
    return {std::nullopt, EngineOutcome::Failed, EngineError::InvalidPe};
  }
  if (progress) {
    progress(request.imageKind == pe::PeImageKind::DynamicLibrary
                 ? EngineStage::LoadingTargetLibrary
                 : EngineStage::Launching);
  }
  std::optional<PeCapturedRun> captured;
  auto debugResult = debugging::WindowsDebugSession::Capture(
      {request.targetPath, request.format, request.imageKind,
       request.entryPointTarget, request.layout->sizeOfImage, request.timeout,
       request.collectRuntimeImports, request.stagedImage, request.requiredBase,
       request.dependencyDirectory},
      [&](dumping::IRemoteMemoryReader const& reader,
          dumping::LoadedImage const& loaded,
          RelativeVirtualAddress resolvedEntryPoint,
          pe::imports::RuntimeModuleSnapshot const& runtimeImports) {
        if (progress) progress(EngineStage::Dumping);
        auto dump = dumping::ProcessImageDumper::Dump(
            reader, loaded, *request.layout, {request.maximumImageSize});
        if (!dump.image) return dump.error;
        captured = PeCapturedRun{std::move(*dump.image), resolvedEntryPoint,
                                 runtimeImports};
        return EngineError::None;
      },
      stopToken);
  if (!debugResult.Succeeded()) {
    auto outcome = EngineOutcome::Failed;
    if (debugResult.error == EngineError::TimedOut)
      outcome = EngineOutcome::TimedOut;
    else if (debugResult.error == EngineError::Cancelled)
      outcome = EngineOutcome::Cancelled;
    else if (debugResult.error == EngineError::OepNotFound)
      outcome = EngineOutcome::OepNotFound;
    return {std::nullopt, outcome, debugResult.error, debugResult.nativeError};
  }
  if (!captured)
    return {std::nullopt, EngineOutcome::Failed, EngineError::DumpIncomplete};
  return {std::move(captured), EngineOutcome::Completed, EngineError::None};
}
}
