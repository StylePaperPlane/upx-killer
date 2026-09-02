#pragma once

#include "Application/Artifacts/ArtifactPublicationUseCase.h"
#include "Application/ELF/Capture/ElfRuntimeCaptureUseCase.h"
#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"
#include "Application/ELF/Reconstruction/ElfImageReconstructionUseCase.h"

namespace upx_killer::engine::application::elf_translation {

class ElfJobContractTranslator final {
 public:
  [[nodiscard]] static contracts::JobResult PreparationFailure(
      elf_preparation::ElfPreparationResult const& result) noexcept;
  [[nodiscard]] static contracts::JobResult CaptureFailure(
      elf_capture::ElfCaptureResult const& result) noexcept;
  [[nodiscard]] static contracts::JobResult ReconstructionFailure(
      elf_reconstruction::ElfReconstructionResult const& result) noexcept;
  [[nodiscard]] static contracts::JobResult Publication(
      artifacts::ArtifactPublicationResult result) noexcept;
};

}  // namespace upx_killer::engine::application::elf_translation
