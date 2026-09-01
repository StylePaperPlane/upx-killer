#pragma once

#include "Application/Backends/IUnpackBackend.h"
#include "Core/ELF/Format/ElfImage.h"

#include <optional>

namespace upx_killer::engine::application {

class ElfBackendCapabilities final {
 public:
  [[nodiscard]] static contracts::BackendManifest Manifest();
  [[nodiscard]] static std::optional<contracts::TargetDescriptor> DescriptorFor(
      elf::ElfImageLayout const& layout) noexcept;
  [[nodiscard]] static bool Supports(elf::ElfImageLayout const& layout) noexcept;
};

}  // namespace upx_killer::engine::application
