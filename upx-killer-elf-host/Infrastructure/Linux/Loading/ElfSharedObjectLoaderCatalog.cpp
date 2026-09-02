#include "Infrastructure/Linux/Loading/ElfSharedObjectLoaderCatalog.h"

namespace upx_killer::elf_host::loading {
std::optional<std::filesystem::path> ElfSharedObjectLoaderCatalog::Resolve(
    engine::elf::ElfClass imageClass) const noexcept {
  try {
    auto const name = imageClass == engine::elf::ElfClass::Bits32
                          ? "upx_killer_elf_so_loader_x86"
                          : "upx_killer_elf_so_loader_x64";
    auto path = directory_ / name;
    return std::filesystem::is_regular_file(path)
               ? std::optional<std::filesystem::path>{std::move(path)}
               : std::nullopt;
  } catch (...) {
    return std::nullopt;
  }
}
}  // namespace upx_killer::elf_host::loading
