#pragma once

#include "Core/PE/Format/PeFormat.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <limits>

namespace upx_killer::engine::pe::format {
template <PeFormat>
struct PeFormatTraits;

template <>
struct PeFormatTraits<PeFormat::Pe32> final {
  using NtHeaders = IMAGE_NT_HEADERS32;
  using OptionalHeader = IMAGE_OPTIONAL_HEADER32;
  using Pointer = std::uint32_t;

  static constexpr PeFormat Format = PeFormat::Pe32;
  static constexpr WORD OptionalHeaderMagic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
  static constexpr WORD Machine = IMAGE_FILE_MACHINE_I386;
  static constexpr WORD RelocationType = IMAGE_REL_BASED_HIGHLOW;
  static constexpr Pointer OrdinalFlag = IMAGE_ORDINAL_FLAG32;
  static constexpr std::size_t PointerSize = sizeof(Pointer);
  static constexpr std::uint64_t CanonicalImageBase = 0x00400000ull;
  static constexpr bool SupportsHighEntropyVa = false;

  [[nodiscard]] static constexpr bool AddressFits(std::uint64_t value) noexcept {
    return value <= std::numeric_limits<Pointer>::max();
  }
};

template <>
struct PeFormatTraits<PeFormat::Pe64> final {
  using NtHeaders = IMAGE_NT_HEADERS64;
  using OptionalHeader = IMAGE_OPTIONAL_HEADER64;
  using Pointer = std::uint64_t;

  static constexpr PeFormat Format = PeFormat::Pe64;
  static constexpr WORD OptionalHeaderMagic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  static constexpr WORD Machine = IMAGE_FILE_MACHINE_AMD64;
  static constexpr WORD RelocationType = IMAGE_REL_BASED_DIR64;
  static constexpr Pointer OrdinalFlag = IMAGE_ORDINAL_FLAG64;
  static constexpr std::size_t PointerSize = sizeof(Pointer);
  static constexpr std::uint64_t CanonicalImageBase = 0x140000000ull;
  static constexpr bool SupportsHighEntropyVa = true;

  [[nodiscard]] static constexpr bool AddressFits(std::uint64_t) noexcept { return true; }
};

using Pe32Traits = PeFormatTraits<PeFormat::Pe32>;
using Pe64Traits = PeFormatTraits<PeFormat::Pe64>;
}
