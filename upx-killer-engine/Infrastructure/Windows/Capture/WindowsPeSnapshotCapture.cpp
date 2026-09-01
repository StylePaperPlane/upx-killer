#include "Infrastructure/Windows/Capture/WindowsPeSnapshotCapture.h"

#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"

namespace {
using upx_killer::engine::application::pe_capture::PeSnapshotCaptureError;
using upx_killer::engine::debugging::DebugSessionError;

PeSnapshotCaptureError MapDebugError(DebugSessionError error) noexcept {
  switch (error) {
    case DebugSessionError::None: return PeSnapshotCaptureError::None;
    case DebugSessionError::UnsupportedHost:
    case DebugSessionError::MachineMismatch:
      return PeSnapshotCaptureError::MachineMismatch;
    case DebugSessionError::InvalidRequest:
      return PeSnapshotCaptureError::InvalidRequest;
    case DebugSessionError::EntryPointNotFound:
      return PeSnapshotCaptureError::EntryPointNotFound;
    case DebugSessionError::ControlledBaseUnavailable:
      return PeSnapshotCaptureError::ControlledBaseUnavailable;
    case DebugSessionError::TargetLibraryLaunchFailed:
      return PeSnapshotCaptureError::TargetLibraryLaunchFailed;
    case DebugSessionError::ProcessLaunchFailed:
      return PeSnapshotCaptureError::ProcessLaunchFailed;
    case DebugSessionError::Cancelled:
      return PeSnapshotCaptureError::Cancelled;
    case DebugSessionError::TimedOut:
      return PeSnapshotCaptureError::TimedOut;
    case DebugSessionError::Wow64Unavailable:
      return PeSnapshotCaptureError::Wow64Unavailable;
    case DebugSessionError::TargetLibraryAttachInvalid:
      return PeSnapshotCaptureError::TargetLibraryAttachInvalid;
    case DebugSessionError::ImportSnapshotFailed:
      return PeSnapshotCaptureError::ImportSnapshotFailed;
    case DebugSessionError::TargetExited:
      return PeSnapshotCaptureError::TargetExited;
    case DebugSessionError::ProtocolFailure:
    case DebugSessionError::CaptureRejected:
      return PeSnapshotCaptureError::DebugProtocolFailed;
  }
  return PeSnapshotCaptureError::DebugProtocolFailed;
}
}

namespace upx_killer::engine::capture {
application::pe_capture::PeSnapshotCaptureResult WindowsPeSnapshotCapture::CaptureOne(
    application::pe_capture::PeSnapshotCaptureRequest const& request,
    std::function<void(EngineStage)> const& progress,
    std::stop_token stopToken) const noexcept {
  using application::pe_capture::PeCapturedRun;
  using application::pe_capture::PeSnapshotCaptureError;
  if (!request.layout) {
    return {std::nullopt, PeSnapshotCaptureError::InvalidRequest};
  }
  if (progress) {
    progress(request.imageKind == pe::PeImageKind::DynamicLibrary
                 ? EngineStage::LoadingTargetLibrary
                 : EngineStage::Launching);
  }
  std::filesystem::path dllLoader;
  if (request.imageKind == pe::PeImageKind::DynamicLibrary) {
    std::uint32_t loaderError{};
    auto resolved = loaders_.Resolve(request.format, loaderError);
    if (!resolved) {
      return {std::nullopt, PeSnapshotCaptureError::DllLoaderUnavailable,
              loaderError};
    }
    dllLoader = std::move(*resolved);
  }
  std::optional<PeCapturedRun> captured;
  auto dumpError = dumping::DumpError::None;
  auto debugResult = debugging::WindowsDebugSession::Capture(
      {request.targetPath, request.format, request.imageKind,
       request.entryPointTarget, request.layout->sizeOfImage, request.timeout,
       request.collectRuntimeImports, request.stagedImage, request.requiredBase,
       request.dependencyDirectory, std::move(dllLoader)},
      [&](dumping::IRemoteMemoryReader const& reader,
          dumping::LoadedImage const& loaded,
          RelativeVirtualAddress resolvedEntryPoint,
          pe::imports::RuntimeModuleSnapshot const& runtimeImports) {
        if (progress) progress(EngineStage::Dumping);
        auto dump = dumping::ProcessImageDumper::Dump(
            reader, loaded, *request.layout, {request.maximumImageSize});
        if (!dump.image) {
          dumpError = dump.error;
          return false;
        }
        captured = PeCapturedRun{std::move(*dump.image), resolvedEntryPoint,
                                 runtimeImports};
        return true;
      },
      stopToken);
  if (!debugResult.Succeeded()) {
    if (debugResult.error == debugging::DebugSessionError::CaptureRejected) {
      auto const error = dumpError == dumping::DumpError::InvalidImage
                             ? PeSnapshotCaptureError::DumpInvalid
                             : PeSnapshotCaptureError::ReadFailed;
      return {std::nullopt, error, debugResult.nativeError};
    }
    return {std::nullopt, MapDebugError(debugResult.error),
            debugResult.nativeError};
  }
  if (!captured)
    return {std::nullopt, PeSnapshotCaptureError::DumpInvalid};
  return {std::move(captured), PeSnapshotCaptureError::None};
}
}
