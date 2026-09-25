#include "pch.h"
#include "UI/Presentation/UpdateCheckPresentation.h"

#include <string_view>

namespace upx_killer::ui::presentation {
namespace {
void ReplaceToken(std::wstring& text, std::wstring_view token,
                  std::wstring_view value) {
  std::size_t offset{};
  while ((offset = text.find(token, offset)) != std::wstring::npos) {
    text.replace(offset, token.size(), value);
    offset += value.size();
  }
}

winrt::hstring FormatVersionResource(
    winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader const&
        resources,
    wchar_t const* resourceKey, std::string const& currentVersion,
    std::string const& latestVersion = {}) {
  std::wstring text{resources.GetString(resourceKey)};
  auto const current = winrt::to_hstring(currentVersion);
  auto const latest = winrt::to_hstring(latestVersion);
  ReplaceToken(text, L"{0}", current);
  ReplaceToken(text, L"{1}", latest);
  return winrt::hstring{text};
}
}

winrt::hstring UpdateCheckPresentation::CurrentVersion(
    std::string const& version) {
  return L"v" + winrt::to_hstring(version);
}

winrt::hstring UpdateCheckPresentation::Result(
    winrt::Microsoft::Windows::ApplicationModel::Resources::ResourceLoader const&
        resources,
    application::UpdateCheckResult const& result) {
  switch (result.availability) {
    case application::UpdateAvailability::Current:
      return FormatVersionResource(resources, L"VersionUpToDateFormat",
                                   result.currentVersion);
    case application::UpdateAvailability::Available:
      return FormatVersionResource(resources, L"VersionUpdateAvailableFormat",
                                   result.currentVersion,
                                   result.latestVersion);
    case application::UpdateAvailability::CheckFailed:
      return FormatVersionResource(resources, L"VersionCheckFailedFormat",
                                   result.currentVersion);
  }
  return CurrentVersion(result.currentVersion);
}
}
