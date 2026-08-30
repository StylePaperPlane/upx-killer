#pragma once

#include "Core/PE/Format/PeFormat.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <utility>
#include <vector>

namespace upx_killer::engine::loading {
class DllLoaderCatalog final {
 public:
  using Registration = std::pair<pe::PeFormat, std::filesystem::path>;

  explicit DllLoaderCatalog(std::vector<Registration> registrations);

  [[nodiscard]] std::optional<std::filesystem::path> Resolve(
      pe::PeFormat format, std::uint32_t& nativeError) const noexcept;

 private:
  std::vector<Registration> registrations_;
};
}
