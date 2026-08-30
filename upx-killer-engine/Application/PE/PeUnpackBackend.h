#pragma once

#include "Application/Backends/IUnpackBackend.h"
#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Application/PE/Capture/PeRuntimeCaptureUseCase.h"
#include "Application/PE/Preparation/PeTargetProbe.h"
#include "Application/PE/Reconstruction/PeImageReconstructionUseCase.h"

namespace upx_killer::engine::application {
class PeUnpackBackend final : public contracts::IUnpackBackend {
 public:
  PeUnpackBackend(
      pe_preparation::PeTargetProbe const& probe,
      pe_preparation::PeTargetPreparationUseCase const& preparation,
      pe_capture::PeRuntimeCaptureUseCase const& capture,
      pe_reconstruction::PeImageReconstructionUseCase const& reconstruction,
      artifacts::ArtifactPublicationUseCase const& publication)
      : probe_(probe),
        preparation_(preparation),
        capture_(capture),
        reconstruction_(reconstruction),
        publication_(publication) {}

  [[nodiscard]] contracts::BackendManifest Manifest() const override;
  [[nodiscard]] contracts::BackendProbeResult Probe(
      contracts::UnpackJobRequest const& request) const noexcept override;
  [[nodiscard]] contracts::JobResult Execute(
      contracts::UnpackJobRequest const& request,
      contracts::ProgressCallback const& progress,
      std::stop_token stopToken) noexcept override;

 private:
  pe_preparation::PeTargetProbe const& probe_;
  pe_preparation::PeTargetPreparationUseCase const& preparation_;
  pe_capture::PeRuntimeCaptureUseCase const& capture_;
  pe_reconstruction::PeImageReconstructionUseCase const& reconstruction_;
  artifacts::ArtifactPublicationUseCase const& publication_;
};
}
