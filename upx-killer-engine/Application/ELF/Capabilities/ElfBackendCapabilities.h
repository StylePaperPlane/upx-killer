#pragma once

#include "Application/Backends/IUnpackBackend.h"
#include "Core/ELF/Format/ElfImage.h"

namespace upx_killer::engine::application {

class ElfBackendCapabilities final {
 public:
  [[nodiscard]] static contracts::TargetDescriptor Descriptor() noexcept;
  [[nodiscard]] static contracts::BackendManifest Manifest();
  [[nodiscard]] static bool Supports(elf::ElfImageLayout const& layout) noexcept;
};

}  // namespace upx_killer::engine::application
