#pragma once

#include "Application/ELF/Preparation/ElfTargetPreparationUseCase.h"

namespace upx_killer::engine::application::elf_preparation {

class ElfTargetProbe final {
 public:
  explicit ElfTargetProbe(IElfSourceReader const& reader) : reader_(reader) {}
  [[nodiscard]] contracts::BackendProbeResult Execute(
      contracts::UnpackJobRequest const& request) const noexcept;

 private:
  IElfSourceReader const& reader_;
};

}  // namespace upx_killer::engine::application::elf_preparation
