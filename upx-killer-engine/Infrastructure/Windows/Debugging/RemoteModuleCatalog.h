#pragma once

#include "Core/PE/Imports/ImportTypes.h"
#include "Core/PE/Format/PeFormat.h"

#include <Windows.h>

#include <cstdint>
#include <optional>

namespace upx_killer::engine::debugging {
struct RemoteModuleCatalogResult {
  pe::imports::RuntimeModuleSnapshot snapshot;
  std::uint32_t nativeError{};

  [[nodiscard]] bool Succeeded() const noexcept { return nativeError == ERROR_SUCCESS; }
};

class RemoteModuleCatalog final {
 public:
  [[nodiscard]] static RemoteModuleCatalogResult Capture(HANDLE process, DWORD processId,
                                                         pe::PeFormat expectedFormat,
                                                         std::optional<LoadedAddress> excludedBase =
                                                             std::nullopt) noexcept;
};
}
