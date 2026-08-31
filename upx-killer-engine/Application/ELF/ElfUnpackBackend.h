#pragma once

#include "Application/Artifacts/IArtifactPublisher.h"
#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"
#include "Application/ELF/Preparation/ElfTargetProbe.h"
#include "Application/ELF/Reconstruction/ElfImageReconstructionUseCase.h"

namespace upx_killer::engine::application {

class ElfUnpackBackend final : public contracts::IUnpackBackend {
 public:
  ElfUnpackBackend(
      elf_preparation::ElfTargetProbe const& probe,
      elf_preparation::ElfTargetPreparationUseCase const& preparation,
      elf_capture::ElfRuntimeCaptureUseCase const& capture,
      elf_reconstruction::ElfImageReconstructionUseCase const& reconstruction,
      artifacts::IArtifactPublisher const& publisher)
      : probe_(probe),
        preparation_(preparation),
        capture_(capture),
        reconstruction_(reconstruction),
        publisher_(publisher) {}

  [[nodiscard]] contracts::BackendManifest Manifest() const override;
  [[nodiscard]] contracts::BackendProbeResult Probe(
      contracts::UnpackJobRequest const& request) const noexcept override;
  [[nodiscard]] contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      contracts::ProgressCallback const& progress,
      std::stop_token stopToken) noexcept override;

 private:
  elf_preparation::ElfTargetProbe const& probe_;
  elf_preparation::ElfTargetPreparationUseCase const& preparation_;
  elf_capture::ElfRuntimeCaptureUseCase const& capture_;
  elf_reconstruction::ElfImageReconstructionUseCase const& reconstruction_;
  artifacts::IArtifactPublisher const& publisher_;
};

}  // namespace upx_killer::engine::application
