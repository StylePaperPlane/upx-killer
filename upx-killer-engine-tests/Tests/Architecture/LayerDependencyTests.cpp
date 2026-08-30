#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::optional<std::filesystem::path> FindRepositoryRoot() {
  auto current = std::filesystem::current_path();
  for (unsigned level = 0; level < 8; ++level) {
    if (std::filesystem::is_directory(current / "upx-killer-contracts") &&
        std::filesystem::is_directory(current / "upx-killer-engine"))
      return current;
    if (!current.has_parent_path()) break;
    current = current.parent_path();
  }
  return std::nullopt;
}

bool IsSource(std::filesystem::path const& path) {
  return path.extension() == ".h" || path.extension() == ".cpp";
}

std::string ReadText(std::filesystem::path const& path) {
  std::ifstream stream(path, std::ios::binary);
  return {std::istreambuf_iterator<char>{stream}, std::istreambuf_iterator<char>{}};
}

int RequireAbsent(std::filesystem::path const& root,
                  std::vector<std::string_view> const& forbidden,
                  std::string_view rule) {
  int failures{};
  if (std::filesystem::is_regular_file(root)) {
    auto const text = ReadText(root);
    for (auto const token : forbidden) {
      if (text.find(token) == std::string::npos) continue;
      std::cerr << "FAIL: " << rule << " in " << root.string()
                << " (" << token << ")\n";
      ++failures;
    }
    return failures;
  }
  for (auto const& entry : std::filesystem::recursive_directory_iterator(root)) {
    if (!entry.is_regular_file() || !IsSource(entry.path())) continue;
    auto const text = ReadText(entry.path());
    for (auto const token : forbidden) {
      if (text.find(token) == std::string::npos) continue;
      std::cerr << "FAIL: " << rule << " in " << entry.path().string()
                << " (" << token << ")\n";
      ++failures;
    }
  }
  return failures;
}
}

int RunLayerDependencyTests() {
  auto root = FindRepositoryRoot();
  if (!root) {
    std::cerr << "FAIL: architecture tests could not locate repository root\n";
    return 1;
  }

  int failures{};
  failures += RequireAbsent(
      *root / "upx-killer-contracts",
      {"#include <Windows", "#include \"Windows", "winrt/", "Core/PE/",
       "IMAGE_NT_HEADERS", "HANDLE"},
      "Contracts must remain portable and format-neutral");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Application",
      {"#include \"Infrastructure/"},
      "Application must not depend on Infrastructure");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Core",
      {"#include \"Infrastructure/"},
      "Core must not depend on Infrastructure");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Application" / "PE" / "PeUnpackBackend.cpp",
      {"PeParser::", "PeImageFixer", "RelocationReconstructor",
       "WindowsDebugSession", "ReadProcessMemory", "CreateFileW"},
      "PE backend must only coordinate use cases");
  return failures;
}
