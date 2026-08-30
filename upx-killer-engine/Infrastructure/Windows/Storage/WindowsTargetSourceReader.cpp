#include "Infrastructure/Windows/Storage/WindowsTargetSourceReader.h"

#include <algorithm>
#include <cwctype>
#include <fstream>

namespace {
std::filesystem::path ResolveDependencyDirectory(
    std::filesystem::path const& targetPath) noexcept {
  try {
    auto directory = targetPath.parent_path();
    if (directory.empty()) return directory;
    auto const mainDirectory = directory / L"main";
    std::error_code error;
    if (!std::filesystem::is_directory(mainDirectory, error) || error) return directory;
    for (auto const& entry : std::filesystem::directory_iterator(mainDirectory, error)) {
      if (error) break;
      if (!entry.is_regular_file(error) || error) continue;
      auto extension = entry.path().extension().wstring();
      std::transform(extension.begin(), extension.end(), extension.begin(),
                     [](wchar_t value) {
                       return static_cast<wchar_t>(std::towlower(value));
                     });
      if (extension == L".dll") return mainDirectory;
    }
    return directory;
  } catch (...) {
    return targetPath.parent_path();
  }
}
}

namespace upx_killer::engine::storage {
application::pe_preparation::TargetSourceReadResult WindowsTargetSourceReader::Read(
    std::filesystem::path const& targetPath,
    std::uint64_t maximumSize) const noexcept {
  try {
    if (targetPath.empty() || maximumSize == 0) return {};
    std::ifstream input(targetPath, std::ios::binary | std::ios::ate);
    if (!input) return {};
    auto const end = input.tellg();
    if (end <= 0 || static_cast<std::uint64_t>(end) > maximumSize) return {};
    application::pe_preparation::TargetSource source{};
    source.bytes.resize(static_cast<std::size_t>(end));
    input.seekg(0);
    input.read(reinterpret_cast<char*>(source.bytes.data()),
               static_cast<std::streamsize>(source.bytes.size()));
    if (!input) return {};
    source.dependencyDirectory = ResolveDependencyDirectory(targetPath);
    return {std::move(source), 0};
  } catch (...) {
    return {};
  }
}
}
