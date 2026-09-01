#pragma once

#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/PE/Imports/ImportTypes.h"

#include <chrono>
#include <filesystem>
#include <functional>
#include <stop_token>
#include <span>
#include <variant>

namespace upx_killer::engine::debugging {
enum class DebugSessionError {
  None,
  UnsupportedHost,
  InvalidRequest,
  EntryPointNotFound,
  ControlledBaseUnavailable,
  TargetLibraryLaunchFailed,
  ProcessLaunchFailed,
  Cancelled,
  TimedOut,
  ProtocolFailure,
  MachineMismatch,
  Wow64Unavailable,
  TargetLibraryAttachInvalid,
  ImportSnapshotFailed,
  TargetExited,
  CaptureRejected,
};

struct DebugLaunchRequest {
  std::filesystem::path targetPath;
  pe::PeFormat format{pe::PeFormat::Pe64};
  pe::PeImageKind imageKind{pe::PeImageKind::Executable};
  std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> oepTarget;
  std::uint32_t sizeOfImage{};
  std::chrono::milliseconds timeout{60'000};
  bool collectRuntimeImports{};
  std::span<std::byte const> stagedTargetImage;
  std::optional<LoadedAddress> requiredImageBase;
  // Directory used by the debuggee for relative paths and DLL resolution.
  std::filesystem::path workingDirectory;
  // Resolved by the platform loading catalog; empty for executables.
  std::filesystem::path dllLoader;
};

struct DebugCaptureResult {
  DebugSessionError error{DebugSessionError::None};
  std::uint32_t nativeError{};
  LoadedAddress observedImageBase;

  [[nodiscard]] bool Succeeded() const noexcept { return error == DebugSessionError::None; }
};

using CaptureCallback =
    std::function<bool(dumping::IRemoteMemoryReader const&, dumping::LoadedImage const&,
                       RelativeVirtualAddress, pe::imports::RuntimeModuleSnapshot const&)>;

class WindowsDebugSession final {
 public:
  [[nodiscard]] static DebugCaptureResult Capture(DebugLaunchRequest const& request,
                                                  CaptureCallback const& capture,
                                                  std::stop_token stopToken = {}) noexcept;
};
}
