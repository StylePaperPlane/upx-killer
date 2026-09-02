#pragma once

#include "Core/ELF/Format/ElfImage.h"

#include <filesystem>
#include <optional>

namespace upx_killer::elf_host::loading {

class ElfSharedObjectLoaderCatalog final {
 public:
  explicit ElfSharedObjectLoaderCatalog(std::filesystem::path directory)
      : directory_(std::move(directory)) {}

  [[nodiscard]] std::optional<std::filesystem::path> Resolve(
      engine::elf::ElfClass imageClass) const noexcept;

 private:
  std::filesystem::path directory_;
};

}  // namespace upx_killer::elf_host::loading
