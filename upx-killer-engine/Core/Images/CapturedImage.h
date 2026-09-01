#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace upx_killer::engine::images {
struct ImageAddress {
  std::uint64_t value{};
};

struct ImageOffset {
  std::uint64_t value{};
};

struct CapturedImageRegion {
  ImageOffset offset;
  std::uint64_t size{};
  bool readable{};
  bool writable{};
  bool executable{};
};

struct CapturedImage {
  ImageAddress loadedAddress;
  std::vector<std::byte> bytes;
  std::vector<CapturedImageRegion> regions;
  std::vector<std::string> warnings;
};
}
