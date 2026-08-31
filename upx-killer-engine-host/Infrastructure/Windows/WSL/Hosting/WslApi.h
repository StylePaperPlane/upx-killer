#pragma once

#include <Windows.h>

#include <string_view>

namespace upx_killer::engine_host::wsl {

struct WslLaunchResult {
  HANDLE process{};
  std::uint32_t nativeCode{};
};

class WslApi final {
 public:
  WslApi() noexcept;
  ~WslApi();
  WslApi(WslApi const&) = delete;
  WslApi& operator=(WslApi const&) = delete;

  [[nodiscard]] bool Available() const noexcept { return launch_ != nullptr; }
  [[nodiscard]] WslLaunchResult Launch(
      std::wstring_view distribution, std::wstring_view command,
      HANDLE standardInput, HANDLE standardOutput,
      HANDLE standardError) const noexcept;

 private:
  using LaunchFunction = HRESULT(WINAPI*)(PCWSTR, PCWSTR, BOOL, HANDLE, HANDLE,
                                          HANDLE, HANDLE*);
  HMODULE module_{};
  LaunchFunction launch_{};
};

}  // namespace upx_killer::engine_host::wsl
