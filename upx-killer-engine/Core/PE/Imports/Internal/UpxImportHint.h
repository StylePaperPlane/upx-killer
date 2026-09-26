#pragma once

#include "Core/PE/Imports/Internal/ImportProviderResolver.h"
#include "Core/PE/Parsing/PeParser.h"

#include <cstddef>
#include <span>
#include <vector>

namespace upx_killer::engine::pe::imports::internal {
// Reads the original import descriptors encoded in UPX's decompressed
// extra-info stream. Returns no hints unless the original PE header, stream,
// packed DLL names, and every thunk interval validate together.
class UpxImportHint final {
 public:
  [[nodiscard]] static std::vector<ImportProviderHint> Analyze(
      std::span<std::byte const> dumpedBytes,
      std::span<std::byte const> sourceBytes,
      PeImageLayout const& sourceLayout,
      RelativeVirtualAddress recoveredEntryPoint) noexcept;
};
}
