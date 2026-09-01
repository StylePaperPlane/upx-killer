#pragma once

#include "Core/Images/CapturedImage.h"
#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace upx_killer::engine::dumping {
enum class DumpError {
  None,
  InvalidImage,
  ReadFailed,
};

struct MemoryRegion {
  LoadedAddress base;
  std::uint64_t size{};
  bool readable{};
  bool writable{};
  bool executable{};
};

class IRemoteMemoryReader {
 public:
  virtual ~IRemoteMemoryReader() = default;
  [[nodiscard]] virtual MemoryRegion Query(LoadedAddress address) const = 0;
  [[nodiscard]] virtual std::size_t Read(LoadedAddress address,
                                         std::span<std::byte> destination) const = 0;
};

struct LoadedImage {
  LoadedAddress base;
  std::uint64_t size{};
};

struct DumpLimits {
  std::uint64_t maximumImageSize{1ull << 30};
};

struct DumpResult {
  std::optional<images::CapturedImage> image;
  DumpError error{DumpError::None};

  [[nodiscard]] bool Succeeded() const noexcept { return image.has_value(); }
};

class ProcessImageDumper final {
 public:
  [[nodiscard]] static DumpResult Dump(IRemoteMemoryReader const& reader, LoadedImage loadedImage,
                                       pe::PeImageLayout const& layout, DumpLimits limits) noexcept;
};
}
