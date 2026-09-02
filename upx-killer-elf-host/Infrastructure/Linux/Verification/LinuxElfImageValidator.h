#pragma once

#include "Infrastructure/Linux/Loading/IsolatedElfLoadVerifier.h"

#include <cstdint>
#include <filesystem>

namespace upx_killer::elf_host::verification {

struct LinuxElfValidationResult {
  bool structurallyValid{};
  bool loaderAccepted{};
  std::uint32_t nativeCode{};
};

class LinuxElfImageValidator final {
 public:
  explicit LinuxElfImageValidator(
      loading::IsolatedElfLoadVerifier const& loaderVerifier)
      : loaderVerifier_(loaderVerifier) {}

  [[nodiscard]] LinuxElfValidationResult Validate(
      std::filesystem::path const& imagePath,
      std::filesystem::path const& dependencyDirectory,
      std::uint32_t timeoutMilliseconds) const noexcept;

 private:
  loading::IsolatedElfLoadVerifier const& loaderVerifier_;
};

}  // namespace upx_killer::elf_host::verification
