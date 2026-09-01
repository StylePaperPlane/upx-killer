#pragma once

#include "Core/Targets/TargetDescriptor.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace upx_killer::core {
enum class BinaryFormat {
  Pe32Executable,
  Pe32PlusExecutable,
  Pe32Library,
  Pe32PlusLibrary,
  Elf32Executable,
  Elf64Executable,
  Elf32SharedObject,
  Elf64SharedObject,
};

enum class BinaryArchitecture {
  X86,
  X64,
};

enum class UpxPackingAssessment {
  NotDetected,
  LikelyStandard,
  LikelyModified,
};

struct UpxPackerInformation {
  UpxPackingAssessment assessment{UpxPackingAssessment::NotDetected};
  std::optional<std::string> releaseVersion;
  std::optional<std::uint8_t> packHeaderVersion;
};

enum class InspectionError {
  None,
  FileNotFound,
  AccessDenied,
  TruncatedFile,
  UnsupportedFormat,
  UnsupportedArchitecture,
  IoFailure,
};

struct TargetBinaryInfo {
  std::filesystem::path path;
  std::uint64_t fileSize{};
  BinaryFormat format{};
  BinaryArchitecture architecture{};
  contracts::TargetDescriptor descriptor{};
  UpxPackerInformation packerInformation{};
};

struct InspectionResult {
  std::optional<TargetBinaryInfo> info;
  InspectionError error{InspectionError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return info.has_value(); }
};

// Performs bounded, read-only inspection. It never executes or maps the target.
class TargetBinaryInspector final {
 public:
  [[nodiscard]] static InspectionResult Inspect(std::filesystem::path const& path) noexcept;
};
}  // namespace upx_killer::core
