#include "Application/PE/Capabilities/PeBackendCapabilities.h"

#include <algorithm>
#include <utility>

namespace upx_killer::engine::application {
PeBackendCapabilities::PeBackendCapabilities(
    std::vector<contracts::TargetDescriptor> supportedTargets)
    : supportedTargets_(std::move(supportedTargets)) {
  std::sort(supportedTargets_.begin(), supportedTargets_.end(),
            [](auto const& left, auto const& right) {
              if (left.family != right.family) return left.family < right.family;
              if (left.imageClass != right.imageClass)
                return left.imageClass < right.imageClass;
              if (left.architecture != right.architecture)
                return left.architecture < right.architecture;
              return left.imageKind < right.imageKind;
            });
  supportedTargets_.erase(
      std::unique(supportedTargets_.begin(), supportedTargets_.end()),
      supportedTargets_.end());
}

bool PeBackendCapabilities::Supports(
    contracts::TargetDescriptor const& target) const noexcept {
  return std::find(supportedTargets_.begin(), supportedTargets_.end(), target) !=
         supportedTargets_.end();
}

bool PeBackendCapabilities::Supports(
    pe::PeImageLayout const& layout) const noexcept {
  return Supports(Describe(layout));
}

contracts::BackendManifest PeBackendCapabilities::Manifest(
    std::string backendId) const {
  return {std::move(backendId), supportedTargets_};
}

contracts::TargetDescriptor PeBackendCapabilities::Describe(
    pe::PeImageLayout const& layout) noexcept {
  return {
      contracts::BinaryFamily::Pe,
      layout.format == pe::PeFormat::Pe32
          ? contracts::BinaryClass::Bits32
          : contracts::BinaryClass::Bits64,
      layout.format == pe::PeFormat::Pe32
          ? contracts::CpuArchitecture::X86
          : contracts::CpuArchitecture::X64,
      layout.imageKind == pe::PeImageKind::Executable
          ? contracts::ImageKind::Executable
          : contracts::ImageKind::SharedLibrary,
  };
}
}
