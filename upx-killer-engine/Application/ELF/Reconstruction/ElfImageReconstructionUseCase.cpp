#include "Application/ELF/Reconstruction/ElfImageReconstructionUseCase.h"

namespace upx_killer::engine::application::elf_reconstruction {
ElfReconstructionResult ElfImageReconstructionUseCase::Execute(
    elf::CapturedElfImage const& captured,
    std::uint64_t maximumImageSize) const noexcept {
  auto rebuilt = elf::ElfImageRebuilder::Rebuild(captured, maximumImageSize);
  if (!rebuilt.image)
    return {std::nullopt,
            {contracts::JobOutcome::Failed,
             contracts::ErrorCategory::Reconstruction,
             std::move(rebuilt.detailCode), std::nullopt, 0}};
  auto validation = elf::ElfImageValidator::Validate(*rebuilt.image);
  if (!validation.valid)
    return {std::nullopt,
            {contracts::JobOutcome::Failed,
             contracts::ErrorCategory::Validation,
             std::move(validation.detailCode), std::nullopt, 0}};
  return {std::move(rebuilt.image), {}};
}
}  // namespace upx_killer::engine::application::elf_reconstruction
