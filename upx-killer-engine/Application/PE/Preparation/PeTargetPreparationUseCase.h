#pragma once

#include "Application/PE/Preparation/PeExecutionPlanFactory.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/Unpacking/UnpackTypes.h"

#include <filesystem>
#include <functional>
#include <optional>
#include <variant>
#include <vector>

namespace upx_killer::engine::application::pe_preparation {
enum class PePreparationError {
  None,
  SourceReadFailed,
  InvalidPe,
  UnsupportedPe32,
  UnsupportedArchitecture,
  UnsupportedImageKind,
  EntryPointOutOfRange,
  UnsupportedPacker,
  EntryPointNotFound,
  SourceRelocationsInvalid,
  UnexpectedFailure,
};

struct TargetSource {
  std::vector<std::byte> bytes;
  std::filesystem::path dependencyDirectory;
};

struct TargetSourceReadResult {
  std::optional<TargetSource> source;
  std::uint32_t nativeError{};
};

class ITargetSourceReader {
 public:
  virtual ~ITargetSourceReader() = default;
  [[nodiscard]] virtual TargetSourceReadResult Read(
      std::filesystem::path const& targetPath,
      std::uint64_t maximumSize) const noexcept = 0;
};

struct PreparedPeTarget {
  std::filesystem::path targetPath;
  std::filesystem::path dependencyDirectory;
  std::vector<std::byte> sourceBytes;
  pe::PeImageLayout layout;
  std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> entryPointTarget;
  PeExecutionPlan executionPlan;
  bool hasSourceRelocations{};
};

struct PePreparationResult {
  std::optional<PreparedPeTarget> target;
  PePreparationError error{PePreparationError::None};
  std::uint32_t nativeError{};

  [[nodiscard]] bool Succeeded() const noexcept { return target.has_value(); }
};

class PeTargetPreparationUseCase final {
 public:
  PeTargetPreparationUseCase(ITargetSourceReader const& sourceReader,
                             PeBackendCapabilities const& capabilities)
      : sourceReader_(sourceReader), capabilities_(capabilities) {}

  [[nodiscard]] PePreparationResult Execute(
      UnpackRequest const& request,
      std::function<void(EngineStage)> const& progress = {}) const noexcept;

 private:
  ITargetSourceReader const& sourceReader_;
  PeBackendCapabilities const& capabilities_;
};
}
