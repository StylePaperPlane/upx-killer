#include "Infrastructure/Windows/Verification/WindowsPeImageValidator.h"

#include "Core/PE/Exports/ExportDirectoryAnalyzer.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Infrastructure/Windows/Debugging/Loading/DebugTargetLoader.h"

#include <Windows.h>

#include <fstream>
#include <vector>

namespace {
using namespace upx_killer::engine;

bool ValidateMapping(std::filesystem::path const& path, pe::PeImageKind kind,
                     bool& exportsValid,
                     std::uint32_t& nativeError) noexcept {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    nativeError = GetLastError();
    return false;
  }
  HANDLE mapping = CreateFileMappingW(
      file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
  if (!mapping) {
    nativeError = GetLastError();
    CloseHandle(file);
    return false;
  }
  void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
  if (!view) nativeError = GetLastError();
  exportsValid = kind == pe::PeImageKind::Executable;
  if (view && kind == pe::PeImageKind::DynamicLibrary) {
    try {
      auto const* dos = static_cast<IMAGE_DOS_HEADER const*>(view);
      auto const* signature = reinterpret_cast<DWORD const*>(
          static_cast<std::byte const*>(view) + dos->e_lfanew);
      auto const* fileHeader =
          reinterpret_cast<IMAGE_FILE_HEADER const*>(signature + 1);
      auto const* magic = reinterpret_cast<WORD const*>(fileHeader + 1);
      std::uint32_t imageSize{};
      if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        imageSize = reinterpret_cast<IMAGE_OPTIONAL_HEADER32 const*>(magic)
                        ->SizeOfImage;
      else if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        imageSize = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 const*>(magic)
                        ->SizeOfImage;
      if (imageSize != 0) {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if (input) {
          auto const length = input.tellg();
          if (length >= 0) {
            std::vector<std::byte> fileBytes(static_cast<std::size_t>(length));
            input.seekg(0);
            input.read(reinterpret_cast<char*>(fileBytes.data()), length);
            auto parsed = pe::PeParser::Parse(fileBytes);
            if (parsed.layout) {
              auto exports = pe::exports::ExportDirectoryAnalyzer::AnalyzeMapped(
                  {static_cast<std::byte const*>(view), imageSize},
                  *parsed.layout);
              exportsValid = exports.Succeeded();
            }
          }
        }
      }
    } catch (...) {
      exportsValid = false;
    }
  }
  if (view) UnmapViewOfFile(view);
  CloseHandle(mapping);
  CloseHandle(file);
  return view != nullptr;
}
}

namespace upx_killer::engine::verification {
application::artifacts::ArtifactValidationResult
WindowsPeImageValidator::Validate(
    application::artifacts::ArtifactValidationRequest const& request)
    const noexcept {
  application::artifacts::ArtifactValidationResult result{};
  if (request.target.family != contracts::BinaryFamily::Pe ||
      request.imagePath.empty() || request.timeoutMilliseconds == 0) {
    result.nativeError = ERROR_INVALID_PARAMETER;
    return result;
  }

  auto const imageKind =
      request.target.imageKind == contracts::ImageKind::SharedLibrary
          ? pe::PeImageKind::DynamicLibrary
          : pe::PeImageKind::Executable;
  result.loaderMappable = ValidateMapping(
      request.imagePath, imageKind, result.exportsValid, result.nativeError);
  if (!result.loaderMappable || !result.exportsValid) return result;

  std::filesystem::path dllLoader;
  if (imageKind == pe::PeImageKind::DynamicLibrary) {
    auto const format = request.target.imageClass == contracts::BinaryClass::Bits32
                            ? pe::PeFormat::Pe32
                            : pe::PeFormat::Pe64;
    auto resolved = loaders_.Resolve(format, result.nativeError);
    if (!resolved) return result;
    dllLoader = std::move(*resolved);
  }
  auto command = debugging::loading::DebugTargetLoader::CreateCommand(
      imageKind, request.imagePath, request.dependencyDirectory, dllLoader,
      result.nativeError);
  if (!command) return result;

  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION information{};
  auto const previousErrorMode = SetErrorMode(
      SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  auto const created = CreateProcessW(
      command->application.c_str(), command->commandLine.data(), nullptr,
      nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
      request.dependencyDirectory.empty()
          ? nullptr
          : request.dependencyDirectory.c_str(),
      &startup, &information);
  SetErrorMode(previousErrorMode);
  if (!created) {
    result.nativeError = GetLastError();
    return result;
  }
  auto const wait =
      WaitForSingleObject(information.hProcess, request.timeoutMilliseconds);
  if (wait == WAIT_TIMEOUT) {
    result.timedOut = true;
    TerminateProcess(information.hProcess, ERROR_TIMEOUT);
    WaitForSingleObject(information.hProcess, 5000);
  } else if (wait == WAIT_OBJECT_0) {
    result.completed = true;
    DWORD exitCode{};
    if (GetExitCodeProcess(information.hProcess, &exitCode))
      result.exitCode = exitCode;
    else
      result.nativeError = GetLastError();
  } else {
    result.nativeError = GetLastError();
    TerminateProcess(information.hProcess, ERROR_FUNCTION_FAILED);
    WaitForSingleObject(information.hProcess, 5000);
  }
  CloseHandle(information.hThread);
  CloseHandle(information.hProcess);
  return result;
}
}
