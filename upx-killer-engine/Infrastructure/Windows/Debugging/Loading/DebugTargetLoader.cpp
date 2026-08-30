#include "Infrastructure/Windows/Debugging/Loading/DebugTargetLoader.h"

#include <algorithm>
#include <cwctype>
#include <vector>

namespace {
std::wstring Quote(std::filesystem::path const& path) {
  std::wstring result{L"\""};
  for (auto value : path.wstring()) {
    if (value == L'\"') result += L'\\';
    result += value;
  }
  result += L'\"';
  return result;
}

std::filesystem::path CurrentDirectory() noexcept {
  std::vector<wchar_t> buffer(32768);
  auto const count = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (count == 0 || count >= buffer.size()) return {};
  return std::filesystem::path{std::wstring_view{buffer.data(), count}}.parent_path();
}

std::wstring Normalize(std::filesystem::path path) noexcept {
  std::error_code error;
  path = std::filesystem::weakly_canonical(path, error);
  if (error) return {};
  auto value = path.wstring();
  std::transform(value.begin(), value.end(), value.begin(),
                 [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
  return value;
}
}

namespace upx_killer::engine::debugging::loading {
std::optional<DebugLaunchCommand> DebugTargetLoader::CreateCommand(
    pe::PeImageKind imageKind, std::filesystem::path const& stagedImage,
    std::filesystem::path const& dependencyDirectory, std::uint32_t& nativeError) noexcept {
  nativeError = ERROR_SUCCESS;
  if (stagedImage.empty()) {
    nativeError = ERROR_INVALID_PARAMETER;
    return std::nullopt;
  }
  if (imageKind == pe::PeImageKind::Executable)
    return DebugLaunchCommand{stagedImage, Quote(stagedImage), false};

  auto const loader = CurrentDirectory() / L"upx_killer_dll_loader_x86.exe";
  std::error_code error;
  if (!std::filesystem::is_regular_file(loader, error) || error) {
    nativeError = ERROR_FILE_NOT_FOUND;
    return std::nullopt;
  }
  auto dependencies = dependencyDirectory.empty() ? stagedImage.parent_path()
                                                   : dependencyDirectory;
  return DebugLaunchCommand{
      loader, Quote(loader) + L" " + Quote(stagedImage) + L" " + Quote(dependencies), true};
}

bool DebugTargetLoader::IsTargetDllEvent(HANDLE imageFile,
                                         std::filesystem::path const& stagedImage) noexcept {
  if (!imageFile || imageFile == INVALID_HANDLE_VALUE) return false;
  std::vector<wchar_t> buffer(32768);
  auto const count = GetFinalPathNameByHandleW(imageFile, buffer.data(),
                                                static_cast<DWORD>(buffer.size()),
                                                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (count == 0 || count >= buffer.size()) return false;
  auto loaded = std::wstring{buffer.data(), count};
  if (loaded.rfind(L"\\\\?\\", 0) == 0) loaded.erase(0, 4);
  return Normalize(loaded) == Normalize(stagedImage);
}
}
