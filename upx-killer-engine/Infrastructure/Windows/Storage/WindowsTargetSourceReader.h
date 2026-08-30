#pragma once

#include "Application/PE/Preparation/PeTargetPreparationUseCase.h"

namespace upx_killer::engine::storage {
class WindowsTargetSourceReader final
    : public application::pe_preparation::ITargetSourceReader {
 public:
  [[nodiscard]] application::pe_preparation::TargetSourceReadResult Read(
      std::filesystem::path const& targetPath,
      std::uint64_t maximumSize) const noexcept override;
};
}
