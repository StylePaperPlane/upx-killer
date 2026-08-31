#pragma once

#include <filesystem>

namespace upx_killer::infrastructure {

class LocalSettingsPath final {
 public:
  [[nodiscard]] static std::filesystem::path Resolve() noexcept;
};

}  // namespace upx_killer::infrastructure
