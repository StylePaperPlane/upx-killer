#include "Application/ELF/Reconstruction/ElfImageReconstructionUseCase.h"

namespace upx_killer::engine::application::elf_reconstruction {
ElfReconstructionResult ElfImageReconstructionUseCase::Execute(
    elf::CapturedElfImage const& captured,
    std::uint64_t maximumImageSize) const noexcept {
  try {
    auto rebuilt = elf::ElfImageRebuilder::Rebuild(captured, maximumImageSize);
    if (!rebuilt.image)
      return {std::nullopt, ElfReconstructionError::RebuildFailed,
              std::move(rebuilt.detailCode)};
    auto validation = elf::ElfImageValidator::Validate(*rebuilt.image);
    if (!validation.valid)
      return {std::nullopt, ElfReconstructionError::ValidationFailed,
              std::move(validation.detailCode)};
    return {std::move(rebuilt.image), ElfReconstructionError::None, {}};
  } catch (...) {
    return {std::nullopt, ElfReconstructionError::UnexpectedFailure,
            "elf.reconstruction.unhandled_exception"};
  }
}
}  // namespace upx_killer::engine::application::elf_reconstruction
