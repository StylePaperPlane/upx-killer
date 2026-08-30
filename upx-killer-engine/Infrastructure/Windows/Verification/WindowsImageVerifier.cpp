#include "Infrastructure/Windows/Verification/WindowsImageVerifier.h"

#include "Core/PE/Exports/ExportDirectoryAnalyzer.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Infrastructure/Windows/Debugging/Loading/DebugTargetLoader.h"

#include <Windows.h>

#include <fstream>
#include <span>
#include <vector>

namespace {
using namespace upx_killer::engine;

bool ValidateMapping(std::filesystem::path const& path, pe::PeImageKind kind,
                     bool& exportsValid, std::uint32_t& nativeError) noexcept {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    nativeError = GetLastError();
    return false;
  }
  HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE,
                                      0, 0, nullptr);
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
      auto const* fileHeader = reinterpret_cast<IMAGE_FILE_HEADER const*>(signature + 1);
      auto const* magic = reinterpret_cast<WORD const*>(fileHeader + 1);
      std::uint32_t imageSize{};
      if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        imageSize = reinterpret_cast<IMAGE_OPTIONAL_HEADER32 const*>(magic)->SizeOfImage;
      else if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        imageSize = reinterpret_cast<IMAGE_OPTIONAL_HEADER64 const*>(magic)->SizeOfImage;
      if (imageSize != 0) {
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        std::vector<std::byte> fileBytes(static_cast<std::size_t>(input.tellg()));
        input.seekg(0);
        input.read(reinterpret_cast<char*>(fileBytes.data()),
                   static_cast<std::streamsize>(fileBytes.size()));
        auto parsed = pe::PeParser::Parse(fileBytes);
        if (parsed.layout) {
          auto exports = pe::exports::ExportDirectoryAnalyzer::AnalyzeMapped(
              {static_cast<std::byte const*>(view), imageSize}, *parsed.layout);
          exportsValid = exports.Succeeded();
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
WindowsImageVerificationResult WindowsImageVerifier::Verify(
    WindowsImageVerificationRequest const& request) noexcept {
  WindowsImageVerificationResult result{};
  if (request.image.empty() || request.timeoutMilliseconds == 0) {
    result.nativeError = ERROR_INVALID_PARAMETER;
    return result;
  }
  result.loaderMappable = ValidateMapping(request.image, request.imageKind,
                                          result.exportsValid, result.nativeError);
  if (!result.loaderMappable || !result.exportsValid) return result;

  auto command = debugging::loading::DebugTargetLoader::CreateCommand(
      request.imageKind, request.image, request.dependencyDirectory, result.nativeError);
  if (!command) return result;
  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESHOWWINDOW;
  startup.wShowWindow = SW_HIDE;
  PROCESS_INFORMATION information{};
  auto const previousErrorMode =
      SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  auto const created = CreateProcessW(
      command->application.c_str(), command->commandLine.data(), nullptr, nullptr, FALSE,
      CREATE_NO_WINDOW, nullptr,
      request.dependencyDirectory.empty() ? nullptr : request.dependencyDirectory.c_str(),
      &startup, &information);
  SetErrorMode(previousErrorMode);
  if (!created) {
    result.nativeError = GetLastError();
    return result;
  }
  auto const wait = WaitForSingleObject(information.hProcess, request.timeoutMilliseconds);
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
