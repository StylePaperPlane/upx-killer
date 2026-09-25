#include "pch.h"
#include "Application/Updates/UpdateCheckWorkflow.h"

#include <array>
#include <charconv>
#include <cstdint>
#include <string_view>

namespace upx_killer::application {
namespace {
struct SemanticVersion {
  std::array<std::uint32_t, 3> parts{};
  std::string normalized;
};

std::optional<SemanticVersion> ParseVersion(std::string_view value) noexcept {
  if (!value.empty() && (value.front() == 'v' || value.front() == 'V'))
    value.remove_prefix(1);
  if (value.empty()) return std::nullopt;

  SemanticVersion parsed;
  parsed.normalized.assign(value);
  std::size_t begin{};
  for (std::size_t index = 0; index < parsed.parts.size(); ++index) {
    auto const end = index + 1 == parsed.parts.size()
                         ? value.size()
                         : value.find('.', begin);
    if (end == std::string_view::npos || end == begin) return std::nullopt;
    auto const token = value.substr(begin, end - begin);
    std::uint32_t part{};
    auto const conversion =
        std::from_chars(token.data(), token.data() + token.size(), part);
    if (conversion.ec != std::errc{} ||
        conversion.ptr != token.data() + token.size())
      return std::nullopt;
    parsed.parts[index] = part;
    begin = end + 1;
  }
  return parsed;
}
}  // namespace

UpdateCheckWorkflow::UpdateCheckWorkflow(
    std::shared_ptr<IReleaseCatalog> releaseCatalog)
    : releaseCatalog_(std::move(releaseCatalog)) {}

std::string UpdateCheckWorkflow::CurrentVersion() const {
  return CurrentApplicationVersion;
}

UpdateCheckResult UpdateCheckWorkflow::Check() const noexcept {
  UpdateCheckResult result;
  result.currentVersion = CurrentApplicationVersion;
  if (!releaseCatalog_) return result;

  auto const current = ParseVersion(CurrentApplicationVersion);
  auto const latestValue = releaseCatalog_->LatestStableVersion();
  if (!current || !latestValue) return result;
  auto const latest = ParseVersion(*latestValue);
  if (!latest) return result;

  result.latestVersion = latest->normalized;
  result.availability = latest->parts > current->parts
                            ? UpdateAvailability::Available
                            : UpdateAvailability::Current;
  return result;
}

}  // namespace upx_killer::application
