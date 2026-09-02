#pragma once

#include "Core/ELF/Format/ElfImage.h"
#include "Infrastructure/Linux/Loading/ElfSharedObjectLoaderCatalog.h"

#include <cstdint>
#include <filesystem>

namespace upx_killer::elf_host::loading {

struct IsolatedElfLoadResult {
  bool accepted{};
  std::uint32_t nativeCode{};
};

class IsolatedElfLoadVerifier final {
 public:
  explicit IsolatedElfLoadVerifier(
      ElfSharedObjectLoaderCatalog const& loaders)
      : loaders_(loaders) {}

  [[nodiscard]] IsolatedElfLoadResult Verify(
      std::filesystem::path const& imagePath,
      engine::elf::ElfImageLayout const& layout,
      std::filesystem::path const& dependencyDirectory,
      std::uint32_t timeoutMilliseconds) const noexcept;

 private:
  ElfSharedObjectLoaderCatalog const& loaders_;
};

}  // namespace upx_killer::elf_host::loading
