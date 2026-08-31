#include "Application/PE/Capabilities/PeBackendCapabilities.h"

#include <iostream>
#include <string_view>

int RunPeBackendCapabilitiesTests() {
  using namespace upx_killer;
  using namespace upx_killer::engine;
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };
  contracts::TargetDescriptor const pe32Exe{
      contracts::BinaryFamily::Pe, contracts::BinaryClass::Bits32,
      contracts::CpuArchitecture::X86, contracts::ImageKind::Executable};
  contracts::TargetDescriptor const pe64Exe{
      contracts::BinaryFamily::Pe, contracts::BinaryClass::Bits64,
      contracts::CpuArchitecture::X64, contracts::ImageKind::Executable};
  contracts::TargetDescriptor const pe32Dll{
      contracts::BinaryFamily::Pe, contracts::BinaryClass::Bits32,
      contracts::CpuArchitecture::X86, contracts::ImageKind::SharedLibrary};
  contracts::TargetDescriptor const pe64Dll{
      contracts::BinaryFamily::Pe, contracts::BinaryClass::Bits64,
      contracts::CpuArchitecture::X64, contracts::ImageKind::SharedLibrary};
  application::PeBackendCapabilities capabilities{
      {pe32Dll, pe64Dll, pe32Exe, pe64Exe, pe32Exe}};
  auto manifest = capabilities.Manifest("pe.test");
  expect(manifest.capabilities.size() == 4 &&
             capabilities.Supports(pe32Exe) &&
             capabilities.Supports(pe64Exe) &&
             capabilities.Supports(pe32Dll) &&
             capabilities.Supports(pe64Dll),
         "manifest and runtime support share one deduplicated capability source");

  pe::PeImageLayout layout{};
  layout.format = pe::PeFormat::Pe32;
  layout.imageKind = pe::PeImageKind::DynamicLibrary;
  expect(capabilities.Supports(layout) &&
             application::PeBackendCapabilities::Describe(layout) == pe32Dll,
         "parsed PE layouts use the same descriptor mapping as the manifest");
  return failures;
}
