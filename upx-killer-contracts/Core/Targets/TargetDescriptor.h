#pragma once

#include <cstdint>

namespace upx_killer::contracts {
enum class BinaryFamily : std::uint8_t { Pe, Elf };
enum class BinaryClass : std::uint8_t { Bits32, Bits64 };
enum class CpuArchitecture : std::uint8_t { X86, X64 };
enum class ImageKind : std::uint8_t { Executable, SharedLibrary };
enum class ImageAddressing : std::uint8_t {
  PlatformDefault,
  FixedAddress,
  PositionIndependent,
};

struct TargetDescriptor {
  BinaryFamily family{};
  BinaryClass imageClass{};
  CpuArchitecture architecture{};
  ImageKind imageKind{};
  ImageAddressing addressing{ImageAddressing::PlatformDefault};

  friend bool operator==(TargetDescriptor const&, TargetDescriptor const&) = default;
};
}
