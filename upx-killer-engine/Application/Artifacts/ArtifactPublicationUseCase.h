#pragma once

#include "Core/Targets/TargetDescriptor.h"
#include "Core/Unpacking/UnpackTypes.h"

#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace upx_killer::engine::application::artifacts {
enum class ArtifactPublicationError {
  None,
  StageFailed,
  ValidationFailed,
  PromoteFailed,
  UnexpectedFailure,
};

struct PublishedArtifact {
  std::filesystem::path path;
  ArtifactQuality quality{ArtifactQuality::Partial};
  bool loaderMappable{};
  std::vector<std::string> warnings;
};

struct ArtifactStageResult {
  std::optional<std::filesystem::path> temporaryPath;
  std::uint32_t nativeError{};
};

class IArtifactStore {
 public:
  virtual ~IArtifactStore() = default;
  [[nodiscard]] virtual ArtifactStageResult Stage(
      std::filesystem::path const& finalPath,
      std::span<std::byte const> bytes) const noexcept = 0;
  [[nodiscard]] virtual std::uint32_t Promote(
      std::filesystem::path const& temporaryPath,
      std::filesystem::path const& finalPath) const noexcept = 0;
  virtual void Remove(std::filesystem::path const& path) const noexcept = 0;
};

struct ArtifactValidationRequest {
  std::filesystem::path imagePath;
  contracts::TargetDescriptor target;
  std::filesystem::path dependencyDirectory;
  std::uint32_t timeoutMilliseconds{};
};

struct ArtifactValidationResult {
  bool loaderMappable{};
  bool exportsValid{};
  bool completed{};
  bool timedOut{};
  std::uint32_t exitCode{};
  std::uint32_t nativeError{};
};

class IArtifactValidator {
 public:
  virtual ~IArtifactValidator() = default;
  [[nodiscard]] virtual ArtifactValidationResult Validate(
      ArtifactValidationRequest const& request) const noexcept = 0;
};

struct ArtifactPublicationRequest {
  std::filesystem::path finalPath;
  std::vector<std::byte> bytes;
  contracts::TargetDescriptor target;
  std::filesystem::path dependencyDirectory;
  std::uint32_t validationTimeoutMilliseconds{3000};
  ArtifactQuality quality{ArtifactQuality::Partial};
  std::vector<std::string> warnings;
  bool retainFailedOutput{};
};

struct ArtifactPublicationResult {
  std::optional<PublishedArtifact> artifact;
  ArtifactPublicationError error{ArtifactPublicationError::None};
  std::uint32_t nativeError{};

  [[nodiscard]] bool Succeeded() const noexcept { return artifact.has_value(); }
};

class ArtifactPublicationUseCase final {
 public:
  ArtifactPublicationUseCase(IArtifactStore const& store,
                             IArtifactValidator const& validator)
      : store_(store), validator_(validator) {}

  [[nodiscard]] ArtifactPublicationResult Execute(
      ArtifactPublicationRequest request,
      std::function<void(EngineStage)> const& progress = {}) const noexcept;

 private:
  IArtifactStore const& store_;
  IArtifactValidator const& validator_;
};
}
