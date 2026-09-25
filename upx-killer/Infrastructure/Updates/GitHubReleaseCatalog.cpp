#include "pch.h"
#include "Infrastructure/Updates/GitHubReleaseCatalog.h"

#include <winhttp.h>

#include <limits>
#include <string>
#include <vector>

#include <winrt/Windows.Data.Json.h>

#pragma comment(lib, "winhttp.lib")

namespace upx_killer::infrastructure {
namespace {
constexpr wchar_t GitHubHost[] = L"api.github.com";
constexpr wchar_t LatestReleasePath[] =
    L"/repos/StylePaperPlane/upx-killer/releases/latest";
constexpr std::size_t MaximumResponseSize = 64 * 1024;

class InternetHandle final {
 public:
  explicit InternetHandle(HINTERNET value = nullptr) noexcept : value_(value) {}
  ~InternetHandle() {
    if (value_) WinHttpCloseHandle(value_);
  }
  InternetHandle(InternetHandle const&) = delete;
  InternetHandle& operator=(InternetHandle const&) = delete;
  [[nodiscard]] HINTERNET get() const noexcept { return value_; }
  [[nodiscard]] explicit operator bool() const noexcept {
    return value_ != nullptr;
  }

 private:
  HINTERNET value_{};
};

std::optional<std::string> ReadResponse(HINTERNET request) {
  std::string response;
  for (;;) {
    DWORD available{};
    if (!WinHttpQueryDataAvailable(request, &available)) return std::nullopt;
    if (available == 0) break;
    if (available > MaximumResponseSize - response.size()) return std::nullopt;

    std::vector<char> buffer(available);
    DWORD read{};
    if (!WinHttpReadData(request, buffer.data(), available, &read))
      return std::nullopt;
    response.append(buffer.data(), read);
  }
  return response;
}
}  // namespace

std::optional<std::string> GitHubReleaseCatalog::LatestStableVersion()
    const noexcept {
  try {
    auto const userAgent = winrt::hstring{L"upx-killer/"} +
                           winrt::to_hstring(
                               application::CurrentApplicationVersion);
    InternetHandle session{WinHttpOpen(
        userAgent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0)};
    if (!session) return std::nullopt;
    if (!WinHttpSetTimeouts(session.get(), 3000, 3000, 3000, 3000))
      return std::nullopt;

    InternetHandle connection{
        WinHttpConnect(session.get(), GitHubHost, INTERNET_DEFAULT_HTTPS_PORT, 0)};
    if (!connection) return std::nullopt;
    InternetHandle request{WinHttpOpenRequest(
        connection.get(), L"GET", LatestReleasePath, nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE)};
    if (!request) return std::nullopt;

    constexpr wchar_t headers[] =
        L"Accept: application/vnd.github+json\r\n"
        L"X-GitHub-Api-Version: 2022-11-28\r\n";
    if (!WinHttpSendRequest(request.get(), headers, static_cast<DWORD>(-1),
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.get(), nullptr))
      return std::nullopt;

    DWORD status{};
    DWORD statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(
            request.get(), WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
            WINHTTP_NO_HEADER_INDEX) ||
        status != 200)
      return std::nullopt;

    auto const body = ReadResponse(request.get());
    if (!body) return std::nullopt;
    winrt::Windows::Data::Json::JsonObject document{nullptr};
    if (!winrt::Windows::Data::Json::JsonObject::TryParse(
            winrt::to_hstring(*body), document))
      return std::nullopt;
    auto const tag = document.GetNamedString(L"tag_name", L"");
    if (tag.empty()) return std::nullopt;
    return winrt::to_string(tag);
  } catch (...) {
    return std::nullopt;
  }
}

}  // namespace upx_killer::infrastructure
