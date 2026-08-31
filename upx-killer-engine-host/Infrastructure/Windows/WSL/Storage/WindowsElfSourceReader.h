#pragma once

#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"

namespace upx_killer::engine_host::wsl {

class WindowsElfSourceReader final
    : public engine::application::elf_preparation::IElfSourceReader {
 public:
  [[nodiscard]] engine::application::elf_preparation::ElfSourceReadResult Read(
      std::filesystem::path const& path,
      std::uint64_t maximumSize) const noexcept override;
};

}  // namespace upx_killer::engine_host::wsl
