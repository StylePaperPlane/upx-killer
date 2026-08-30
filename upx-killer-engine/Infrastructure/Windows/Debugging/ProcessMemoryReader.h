#pragma once

#include "Core/Dumping/ProcessImageDumper.h"

#include <Windows.h>

namespace upx_killer::engine::debugging {
class ProcessMemoryReader final : public dumping::IRemoteMemoryReader {
 public:
  explicit ProcessMemoryReader(HANDLE process) noexcept : process_(process) {}

  [[nodiscard]] dumping::MemoryRegion Query(LoadedAddress address) const override;
  [[nodiscard]] std::size_t Read(LoadedAddress address,
                                 std::span<std::byte> destination) const override;

 private:
  HANDLE process_{};
};
}
