#pragma once

#include <cstdint>

namespace upx_killer::contracts {
enum class BinaryFamily : std::uint8_t { Pe, Elf };
enum class BinaryClass : std::uint8_t { Bits32, Bits64 };
enum class CpuArchitecture : std::uint8_t { X86, X64 };
enum class ImageKind : std::uint8_t { Executable, SharedLibrary };

struct TargetDescriptor {
  BinaryFamily family{};
  BinaryClass imageClass{};
  CpuArchitecture architecture{};
  ImageKind imageKind{};

  friend bool operator==(TargetDescriptor const&, TargetDescriptor const&) = default;
};
}
