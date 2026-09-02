#pragma once

#include "Application/Artifacts/ArtifactPublicationUseCase.h"

namespace upx_killer::elf_host::storage {

class LinuxArtifactStore final
    : public engine::application::artifacts::IArtifactStore {
 public:
  [[nodiscard]] engine::application::artifacts::ArtifactStageResult Stage(
      std::filesystem::path const& finalPath,
      std::span<std::byte const> bytes) const noexcept override;
  [[nodiscard]] std::uint32_t Promote(
      std::filesystem::path const& temporaryPath,
      std::filesystem::path const& finalPath) const noexcept override;
  void Remove(std::filesystem::path const& path) const noexcept override;
};

}  // namespace upx_killer::elf_host::storage
