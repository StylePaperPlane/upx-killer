#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"

namespace upx_killer::engine::application {
contracts::TargetDescriptor ElfBackendCapabilities::Descriptor() noexcept {
  return {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits64,
          contracts::CpuArchitecture::X64,
          contracts::ImageKind::Executable};
}

contracts::BackendManifest ElfBackendCapabilities::Manifest() {
  return {"elf.linux.upx", {Descriptor()}};
}

bool ElfBackendCapabilities::Supports(
    elf::ElfImageLayout const& layout) noexcept {
  return layout.IsExecutableTarget();
}
}  // namespace upx_killer::engine::application
