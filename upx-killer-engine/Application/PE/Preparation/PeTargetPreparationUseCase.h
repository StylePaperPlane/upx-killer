#pragma once

#include "Application/Unpacking/TargetExecutionPolicy.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/Unpacking/UnpackTypes.h"

#include <filesystem>
#include <functional>
#include <optional>
#include <variant>
#include <vector>

namespace upx_killer::engine::application::pe_preparation {
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
  TargetExecutionPlan executionPlan;
  bool hasSourceRelocations{};
};

struct PePreparationResult {
  std::optional<PreparedPeTarget> target;
  EngineOutcome outcome{EngineOutcome::Failed};
  EngineError error{EngineError::None};
  std::uint32_t nativeError{};

  [[nodiscard]] bool Succeeded() const noexcept { return target.has_value(); }
};

class PeTargetPreparationUseCase final {
 public:
  explicit PeTargetPreparationUseCase(ITargetSourceReader const& sourceReader)
      : sourceReader_(sourceReader) {}

  [[nodiscard]] PePreparationResult Execute(
      UnpackRequest const& request,
      std::function<void(EngineStage)> const& progress = {}) const noexcept;

 private:
  ITargetSourceReader const& sourceReader_;
};
}
