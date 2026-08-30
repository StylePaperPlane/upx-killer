#pragma once

#include "Core/PE/Format/PeFormat.h"

#include <cstdint>
#include <filesystem>

namespace upx_killer::engine::verification {
struct WindowsImageVerificationRequest {
  std::filesystem::path image;
  pe::PeImageKind imageKind{pe::PeImageKind::Executable};
  std::filesystem::path dependencyDirectory;
  std::uint32_t timeoutMilliseconds{};
};

struct WindowsImageVerificationResult {
  bool loaderMappable{};
  bool exportsValid{};
  bool completed{};
  bool timedOut{};
  std::uint32_t exitCode{};
  std::uint32_t nativeError{};
};

class WindowsImageVerifier final {
 public:
  [[nodiscard]] static WindowsImageVerificationResult Verify(
      WindowsImageVerificationRequest const& request) noexcept;
};
}
