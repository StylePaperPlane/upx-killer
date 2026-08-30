#pragma once

#include "Core/PE/Format/PeFormat.h"

#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace upx_killer::engine::debugging::loading {
struct DebugLaunchCommand {
  std::filesystem::path application;
  std::wstring commandLine;
  bool targetArrivesAsDll{};
};

class DebugTargetLoader final {
 public:
  [[nodiscard]] static std::optional<DebugLaunchCommand> CreateCommand(
      pe::PeImageKind imageKind, std::filesystem::path const& stagedImage,
      std::filesystem::path const& dependencyDirectory,
      std::filesystem::path const& dllLoader,
      std::uint32_t& nativeError) noexcept;

  [[nodiscard]] static bool IsTargetDllEvent(HANDLE imageFile,
                                             std::filesystem::path const& stagedImage) noexcept;
};
}
