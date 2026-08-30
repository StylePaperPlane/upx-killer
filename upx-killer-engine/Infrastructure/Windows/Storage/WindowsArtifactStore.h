#pragma once

#include "Application/Artifacts/ArtifactPublicationUseCase.h"

namespace upx_killer::engine::storage {
class WindowsArtifactStore final : public application::artifacts::IArtifactStore {
 public:
  [[nodiscard]] application::artifacts::ArtifactStageResult Stage(
      std::filesystem::path const& finalPath,
      std::span<std::byte const> bytes) const noexcept override;
  [[nodiscard]] std::uint32_t Promote(
      std::filesystem::path const& temporaryPath,
      std::filesystem::path const& finalPath) const noexcept override;
  void Remove(std::filesystem::path const& path) const noexcept override;
};
}
