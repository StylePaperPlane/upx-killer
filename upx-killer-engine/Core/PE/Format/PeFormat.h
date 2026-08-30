#pragma once

#include <cstdint>

namespace upx_killer::engine::pe {
enum class PeFormat : std::uint8_t {
  Pe32,
  Pe64,
};

enum class PeImageKind : std::uint8_t {
  Executable,
  DynamicLibrary,
};

struct SourceLoadPolicy {
  std::uint64_t preferredImageBase{};
  bool dynamicBase{};
  bool highEntropyVa{};
  bool hasRelocations{};
};
}
