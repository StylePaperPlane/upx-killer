#include "Application/ELF/Capabilities/ElfBackendCapabilities.h"

#include <array>

namespace {
using namespace upx_killer;

constexpr std::array<contracts::TargetDescriptor, 6> SupportedTargets{{
    {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits64,
     contracts::CpuArchitecture::X64, contracts::ImageKind::Executable,
     contracts::ImageAddressing::FixedAddress},
    {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits64,
     contracts::CpuArchitecture::X64, contracts::ImageKind::Executable,
     contracts::ImageAddressing::PositionIndependent},
    {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits32,
     contracts::CpuArchitecture::X86, contracts::ImageKind::Executable,
     contracts::ImageAddressing::FixedAddress},
    {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits32,
     contracts::CpuArchitecture::X86, contracts::ImageKind::Executable,
     contracts::ImageAddressing::PositionIndependent},
    {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits64,
     contracts::CpuArchitecture::X64, contracts::ImageKind::SharedLibrary,
     contracts::ImageAddressing::PositionIndependent},
    {contracts::BinaryFamily::Elf, contracts::BinaryClass::Bits32,
     contracts::CpuArchitecture::X86, contracts::ImageKind::SharedLibrary,
     contracts::ImageAddressing::PositionIndependent},
}};

std::optional<contracts::TargetDescriptor> Describe(
    engine::elf::ElfImageLayout const& layout) noexcept {
  contracts::TargetDescriptor descriptor{
      contracts::BinaryFamily::Elf,
      layout.imageClass == engine::elf::ElfClass::Bits32
          ? contracts::BinaryClass::Bits32
          : contracts::BinaryClass::Bits64,
      layout.machine == engine::elf::ElfMachine::X86
          ? contracts::CpuArchitecture::X86
          : contracts::CpuArchitecture::X64,
      layout.imageType == engine::elf::ElfImageType::SharedObject
          ? contracts::ImageKind::SharedLibrary
          : contracts::ImageKind::Executable,
      layout.imageType != engine::elf::ElfImageType::Executable
          ? contracts::ImageAddressing::PositionIndependent
          : contracts::ImageAddressing::FixedAddress};
  return descriptor;
}
}  // namespace

namespace upx_killer::engine::application {
contracts::BackendManifest ElfBackendCapabilities::Manifest() {
  return {"elf.linux.upx",
          {SupportedTargets.begin(), SupportedTargets.end()}};
}

std::optional<contracts::TargetDescriptor>
ElfBackendCapabilities::DescriptorFor(
    elf::ElfImageLayout const& layout) noexcept {
  auto const descriptor = Describe(layout);
  if (!descriptor) return std::nullopt;
  for (auto const& supported : SupportedTargets) {
    if (supported == *descriptor) return descriptor;
  }
  return std::nullopt;
}

bool ElfBackendCapabilities::Supports(
    elf::ElfImageLayout const& layout) noexcept {
  return DescriptorFor(layout).has_value();
}
}  // namespace upx_killer::engine::application
