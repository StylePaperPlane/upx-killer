#pragma once

#include "Core/ELF/Reconstruction/ElfImageRebuilder.h"
#include "Core/ELF/Validation/ElfImageValidator.h"
#include "Core/Jobs/UnpackJob.h"

namespace upx_killer::engine::application::elf_reconstruction {

enum class ElfReconstructionError {
  None,
  RebuildFailed,
  ValidationFailed,
  UnexpectedFailure,
};

struct ElfReconstructionResult {
  std::optional<std::vector<std::byte>> bytes;
  ElfReconstructionError error{ElfReconstructionError::None};
  std::string detailCode;
};

class ElfImageReconstructionUseCase final {
 public:
  [[nodiscard]] ElfReconstructionResult Execute(
      elf::CapturedElfImage const& captured,
      std::uint64_t maximumImageSize) const noexcept;
};

}  // namespace upx_killer::engine::application::elf_reconstruction
