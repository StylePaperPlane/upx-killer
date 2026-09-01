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

int RequirePresent(std::filesystem::path const& path,
                   std::vector<std::string_view> const& required,
                   std::string_view rule) {
  auto const text = ReadText(path);
  int failures{};
  for (auto const token : required) {
    if (text.find(token) != std::string::npos) continue;
    std::cerr << "FAIL: " << rule << " in " << path.string()
              << " (missing " << token << ")\n";
    ++failures;
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
      *root / "upx-killer-inspection",
      {"#include <Windows", "#include \"Windows", "winrt/", "Infrastructure/",
       "Core/PE/", "Core/ELF/", "IMAGE_NT_HEADERS", "Elf64_", "Elf32_"},
      "Binary inspection must remain portable and expose no native PE/ELF structures");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Application",
      {"#include \"Infrastructure/", "#include <Windows",
       "#include \"Windows", "winrt/", "IMAGE_DIRECTORY_ENTRY_",
       "IMAGE_DLLCHARACTERISTICS_", "IMAGE_FILE_RELOCS_STRIPPED",
       "Core/ELF/Format/Internal/ElfClassTraits.h"},
      "Application must remain platform-neutral and not depend on Infrastructure");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Core",
      {"#include \"Infrastructure/"},
      "Core must not depend on Infrastructure");
  failures += RequireAbsent(
      *root / "upx-killer-engine",
      {"EngineError", "EngineResult", "EngineArtifact", "EngineOutcome"},
      "Engine modules must expose local result and error types");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Core" / "Images" / "CapturedImage.h",
      {"Core/", "RelativeVirtualAddress", "LoadedAddress", "FileOffset",
       "PeImage", "ElfImage", "PE/", "ELF/"},
      "Captured image must remain format-neutral and self-contained");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Application" / "PE" / "PeUnpackBackend.cpp",
      {"PeParser::", "PeImageFixer", "RelocationReconstructor",
       "WindowsDebugSession", "ReadProcessMemory", "CreateFileW",
       "DetailCode(", "MapStage(", "MapOutcome(", "Category("},
      "PE backend must only coordinate use cases");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Core" / "PE" / "Sections",
      {"Core/Dumping/ProcessImageDumper.h", "dumping::DumpedImage",
       "dumping::DumpedMemoryRegion"},
      "PE section reconstruction must consume the neutral captured image model");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Core" / "PE" / "Fixing",
      {"Core/Dumping/ProcessImageDumper.h", "dumping::DumpedImage",
       "dumping::DumpedMemoryRegion"},
      "PE fixing must consume the neutral captured image model");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Application" / "ELF" /
          "ElfUnpackBackend.cpp",
      {"ElfParser::", "ElfImageRebuilder", "ptrace", "/proc/", "WslLaunch",
       "LinuxProcessMemory"},
      "ELF backend must only coordinate use cases");
  failures += RequireAbsent(
      *root / "upx-killer-engine" / "Application" / "Artifacts",
      {"Core/PE/", "PreparedPeTarget", "ReconstructedPeImage", "PeImageKind"},
      "Artifact publication must remain format-neutral");
  failures += RequireAbsent(
      *root / "upx-killer" / "Infrastructure" / "EngineHost" /
          "EngineHostClient.cpp",
      {"TemporaryFileSettings", "temp_directory_path", "remove_all",
       "CreateProcessW", "CreatePipe"},
      "Engine host client must delegate workspace and process concerns");
  failures += RequireAbsent(
      *root / "upx-killer-engine-host" / "Infrastructure" / "Windows" /
          "WSL",
      {"Core/ELF/", "ElfParser::", "ElfImageRebuilder", "ptrace"},
      "Windows WSL adapters must use portable contracts, not ELF internals");
  failures += RequireAbsent(
      *root / "upx-killer-elf-host" / "Infrastructure",
      {"Core/ELF/Format/Internal/ElfClassTraits.h"},
      "Linux adapters must not depend on internal ELF class traits");
  failures += RequireAbsent(
      *root / "upx-killer-elf-host" / "CMakeLists.txt",
      {"${CONTRACTS_ROOT}/", "${ENGINE_ROOT}/"},
      "ELF Host CMake must consume module targets instead of external sources");
  failures += RequirePresent(
      *root / "upx-killer-contracts" / "CMakeLists.txt",
      {"add_library(upx_killer_contracts", "upx_killer::contracts"},
      "Contracts must own its portable CMake target");
  failures += RequirePresent(
      *root / "upx-killer-engine" / "CMakeLists.txt",
      {"add_library(upx_killer_elf_core", "add_library(upx_killer_elf_application",
       "target_link_libraries(upx_killer_elf_application"},
      "ELF Core and Application must own separate CMake targets");
  failures += RequirePresent(
      *root / "upx-killer-elf-host" / "CMakeLists.txt",
      {"add_subdirectory(", "add_library(upx_killer_elf_linux",
       "target_link_libraries(upx_killer_elf_host"},
      "ELF Host must compose owned module targets");
  failures += RequirePresent(
      *root / ".gitignore", {"/artifacts/"},
      "Generated artifact output must be ignored only at repository root");
  failures += RequireAbsent(
      *root / ".gitignore", {"\nartifacts/", "\r\nartifacts/"},
      "Git ignore rules must not hide the Application/Artifacts source module");
  return failures;
}
