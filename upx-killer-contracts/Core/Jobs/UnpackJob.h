#pragma once

#include "Core/Images/Artifact.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace upx_killer::contracts {
enum class EntryPointAddressKind : std::uint8_t {
  RelativeVirtualAddress,
  VirtualAddress,
  FileOffset,
};

struct EntryPointHint {
  EntryPointAddressKind kind{EntryPointAddressKind::RelativeVirtualAddress};
  std::uint64_t value{};
};

struct UnpackJobRequest {
  std::filesystem::path targetPath;
  std::filesystem::path outputPath;
  std::optional<EntryPointHint> entryPoint;
  std::uint32_t timeoutMilliseconds{60'000};
  std::uint64_t maximumImageSize{1ull << 30};
  bool retainFailedOutput{};
};

enum class JobOutcome : std::uint8_t {
  Completed,
  Partial,
  UnsupportedTarget,
  Cancelled,
  TimedOut,
  Failed,
};

enum class ErrorCategory : std::uint8_t {
  None,
  InvalidRequest,
  UnsupportedTarget,
  Configuration,
  Input,
  Execution,
  Reconstruction,
  Validation,
  Storage,
  Protocol,
  Cancelled,
  TimedOut,
  Internal,
};

enum class JobStage : std::uint8_t {
  ValidatingTarget,
  DiscoveringEntryPoint,
  LoadingTarget,
  CapturingImage,
  RebuildingImports,
  CapturingRelocations,
  RebuildingImage,
  ValidatingArtifact,
  Completed,
};

struct ProgressEvent {
  JobStage stage{JobStage::ValidatingTarget};
  std::string detailCode;
};

struct JobResult {
  JobOutcome outcome{JobOutcome::Failed};
  ErrorCategory category{ErrorCategory::Internal};
  std::string detailCode;
  std::optional<JobArtifact> artifact;
  std::uint32_t nativeCode{};
};
}
