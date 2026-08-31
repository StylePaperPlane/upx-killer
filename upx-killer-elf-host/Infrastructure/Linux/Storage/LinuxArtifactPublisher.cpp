#include "Infrastructure/Linux/Storage/LinuxArtifactPublisher.h"

#include <sys/stat.h>

#include <cerrno>
#include <fstream>

namespace upx_killer::elf_host::storage {
contracts::JobResult LinuxArtifactPublisher::Publish(
    engine::application::artifacts::PublishArtifactRequest const& request,
    contracts::ProgressCallback const& progress) const noexcept {
  auto stagedPath = request.outputPath;
  stagedPath += ".part";
  try {
    std::error_code error;
    std::filesystem::create_directories(request.outputPath.parent_path(), error);
    if (error)
      return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Storage,
              "artifact.directory.create_failed", std::nullopt,
              static_cast<std::uint32_t>(error.value())};
    std::ofstream stream(stagedPath, std::ios::binary | std::ios::trunc);
    if (!stream)
      return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Storage,
              "artifact.write_failed", std::nullopt,
              static_cast<std::uint32_t>(errno)};
    stream.write(reinterpret_cast<char const*>(request.bytes.data()),
                 static_cast<std::streamsize>(request.bytes.size()));
    stream.close();
    if (!stream || chmod(stagedPath.c_str(), 0700) != 0) {
      auto const native = static_cast<std::uint32_t>(errno);
      if (!request.retainFailedOutput) std::filesystem::remove(stagedPath, error);
      return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Storage,
              "artifact.write_failed", std::nullopt, native};
    }
    if (progress)
      progress({contracts::JobStage::ValidatingArtifact,
                "elf.progress.validating_artifact"});
    auto validation = validator_.Validate(
        stagedPath, request.dependencyDirectory, request.timeoutMilliseconds);
    if (!validation.structurallyValid || !validation.loaderAccepted) {
      if (!request.retainFailedOutput) std::filesystem::remove(stagedPath, error);
      return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Validation,
              "elf.artifact.validation_failed", std::nullopt,
              validation.nativeCode};
    }
    std::filesystem::remove(request.outputPath, error);
    error.clear();
    std::filesystem::rename(stagedPath, request.outputPath, error);
    if (error) {
      if (!request.retainFailedOutput) std::filesystem::remove(stagedPath, error);
      return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Storage,
              "artifact.promote_failed", std::nullopt,
              static_cast<std::uint32_t>(error.value())};
    }
    if (progress)
      progress({contracts::JobStage::Completed, "job.completed"});
    contracts::JobArtifact artifact{request.outputPath,
                                    contracts::ArtifactQuality::Complete, true,
                                    {}};
    return {contracts::JobOutcome::Completed, contracts::ErrorCategory::None,
            "job.completed", std::move(artifact), 0};
  } catch (...) {
    std::error_code ignored;
    if (!request.retainFailedOutput) std::filesystem::remove(stagedPath, ignored);
    return {contracts::JobOutcome::Failed, contracts::ErrorCategory::Storage,
            "artifact.write_failed", std::nullopt,
            static_cast<std::uint32_t>(EIO)};
  }
}
}  // namespace upx_killer::elf_host::storage
