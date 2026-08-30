#pragma once

#include "Core/PE/Imports/ImportTypes.h"

#include <Windows.h>

#include <cstddef>
#include <span>
#include <vector>

namespace upx_killer::engine::debugging::imports {
class AppCompatImportAliasResolver final {
 public:
  [[nodiscard]] static std::vector<pe::imports::RuntimeExport> Resolve(
      HANDLE process, LoadedAddress shimBase, std::span<std::byte const> shimImage,
      pe::imports::RuntimeModuleSnapshot const& runtime) noexcept;
};
}
