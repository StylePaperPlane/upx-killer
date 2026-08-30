#pragma once

#include "Core/PE/Format/PeFormat.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>

namespace upx_killer::engine::debugging::staging {
class StagedDebugTarget final {
 public:
  StagedDebugTarget() = default;
  ~StagedDebugTarget();
  StagedDebugTarget(StagedDebugTarget const&) = delete;
  StagedDebugTarget& operator=(StagedDebugTarget const&) = delete;
  StagedDebugTarget(StagedDebugTarget&& other) noexcept;
  StagedDebugTarget& operator=(StagedDebugTarget&& other) noexcept;

  [[nodiscard]] static std::optional<StagedDebugTarget> Create(
      std::filesystem::path const& sourcePath, pe::PeImageKind imageKind,
      std::span<std::byte const> image,
      std::uint32_t& nativeError) noexcept;

  [[nodiscard]] std::filesystem::path const& ImagePath() const noexcept {
    return executablePath_;
  }

 private:
  void Reset() noexcept;

  std::filesystem::path directory_;
  std::filesystem::path executablePath_;
};
}
