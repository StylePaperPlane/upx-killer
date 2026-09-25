#pragma once

#include <memory>
#include <optional>
#include <string>

namespace upx_killer::application {

inline constexpr char CurrentApplicationVersion[] = "0.00.4";

class IReleaseCatalog {
 public:
  virtual ~IReleaseCatalog() = default;
  [[nodiscard]] virtual std::optional<std::string> LatestStableVersion()
      const noexcept = 0;
};

enum class UpdateAvailability {
  Current,
  Available,
  CheckFailed,
};

struct UpdateCheckResult {
  UpdateAvailability availability{UpdateAvailability::CheckFailed};
  std::string currentVersion;
  std::string latestVersion;
};

class UpdateCheckWorkflow final {
 public:
  explicit UpdateCheckWorkflow(std::shared_ptr<IReleaseCatalog> releaseCatalog);

  [[nodiscard]] std::string CurrentVersion() const;
  [[nodiscard]] UpdateCheckResult Check() const noexcept;

 private:
  std::shared_ptr<IReleaseCatalog> releaseCatalog_;
};

}  // namespace upx_killer::application
