#include "Infrastructure/Windows/WSL/Hosting/WslApi.h"

#include <string>

namespace upx_killer::engine_host::wsl {
WslApi::WslApi() noexcept {
  module_ = LoadLibraryW(L"wslapi.dll");
  if (module_)
    launch_ = reinterpret_cast<LaunchFunction>(
        GetProcAddress(module_, "WslLaunch"));
}

WslApi::~WslApi() {
  if (module_) FreeLibrary(module_);
}

WslLaunchResult WslApi::Launch(
    std::wstring_view distribution, std::wstring_view command,
    HANDLE standardInput, HANDLE standardOutput,
    HANDLE standardError) const noexcept {
  if (!launch_ || distribution.empty() || command.empty())
    return {nullptr, ERROR_NOT_SUPPORTED};
  std::wstring distributionValue{distribution};
  std::wstring commandValue{command};
  HANDLE process{};
  auto const result = launch_(distributionValue.c_str(), commandValue.c_str(),
                              FALSE, standardInput, standardOutput,
                              standardError, &process);
  return SUCCEEDED(result)
             ? WslLaunchResult{process, 0}
             : WslLaunchResult{nullptr, static_cast<std::uint32_t>(result)};
}
}  // namespace upx_killer::engine_host::wsl
