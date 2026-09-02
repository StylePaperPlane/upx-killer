#include "Infrastructure/Windows/WSL/Bridge/WslFileBridge.h"

#include <Windows.h>

#include <algorithm>
#include <atomic>
#include <cwctype>
#include <utility>

namespace {
bool IsSafeDistributionName(std::wstring_view value) noexcept {
  return !value.empty() && value.size() <= 128 &&
         std::all_of(value.begin(), value.end(), [](wchar_t character) {
           return std::iswalnum(character) || character == L'-' ||
                  character == L'_' || character == L'.' || character == L' ';
         });
}

bool IsSharedObject(std::filesystem::path const& path) {
  auto const name = path.filename().wstring();
  return name.ends_with(L".so") || name.find(L".so.") != std::wstring::npos;
}

std::string NarrowAscii(std::wstring_view value) {
  std::string result;
  result.reserve(value.size());
  for (auto const character : value)
    result.push_back(static_cast<char>(character));
  return result;
}
}

namespace upx_killer::engine_host::wsl {
WslStagedJob::~WslStagedJob() { Cleanup(); }

WslStagedJob::WslStagedJob(WslStagedJob&& other) noexcept
    : windowsRoot(std::move(other.windowsRoot)),
      linuxRoot(std::move(other.linuxRoot)),
      linuxTarget(std::move(other.linuxTarget)),
      linuxOutput(std::move(other.linuxOutput)),
      linuxHost(std::move(other.linuxHost)),
      linuxLoader32(std::move(other.linuxLoader32)),
      linuxLoader64(std::move(other.linuxLoader64)),
      ownsRoot_(std::exchange(other.ownsRoot_, false)) {}

WslStagedJob& WslStagedJob::operator=(WslStagedJob&& other) noexcept {
  if (this == &other) return *this;
  Cleanup();
  windowsRoot = std::move(other.windowsRoot);
  linuxRoot = std::move(other.linuxRoot);
  linuxTarget = std::move(other.linuxTarget);
  linuxOutput = std::move(other.linuxOutput);
  linuxHost = std::move(other.linuxHost);
  linuxLoader32 = std::move(other.linuxLoader32);
  linuxLoader64 = std::move(other.linuxLoader64);
  ownsRoot_ = std::exchange(other.ownsRoot_, false);
  return *this;
}

void WslStagedJob::Cleanup() noexcept {
  if (!ownsRoot_ || windowsRoot.empty()) return;
  std::error_code ignored;
  std::filesystem::remove_all(windowsRoot, ignored);
  ownsRoot_ = false;
}

std::uint32_t WslStagedJob::CopyOutputTo(
    std::filesystem::path const& destination) const noexcept {
  try {
    std::error_code error;
    auto const source = windowsRoot / L"output.elf";
    if (!std::filesystem::is_regular_file(source, error))
      return error ? static_cast<std::uint32_t>(error.value())
                   : ERROR_FILE_NOT_FOUND;
    std::filesystem::create_directories(destination.parent_path(), error);
    if (error) return static_cast<std::uint32_t>(error.value());
    auto staged = destination;
    staged += L".wsl-copy";
    std::filesystem::copy_file(source, staged,
                               std::filesystem::copy_options::overwrite_existing,
                               error);
    if (error) return static_cast<std::uint32_t>(error.value());
    std::filesystem::remove(destination, error);
    error.clear();
    std::filesystem::rename(staged, destination, error);
    return static_cast<std::uint32_t>(error.value());
  } catch (...) {
    return ERROR_WRITE_FAULT;
  }
}

std::uint32_t WslFileBridge::EnsureRunning(
    std::wstring_view distribution) const noexcept {
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
  auto nullHandle = CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                &attributes, OPEN_EXISTING, 0, nullptr);
  if (nullHandle == INVALID_HANDLE_VALUE) return GetLastError();
  auto launched = api_.Launch(distribution, L"/bin/true", nullHandle,
                              nullHandle, nullHandle);
  CloseHandle(nullHandle);
  if (!launched.process) return launched.nativeCode;
  auto const wait = WaitForSingleObject(launched.process, 10'000);
  std::uint32_t result{};
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(launched.process, ERROR_TIMEOUT);
    result = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
  } else {
    DWORD exitCode{};
    if (!GetExitCodeProcess(launched.process, &exitCode) || exitCode != 0)
      result = exitCode == 0 ? GetLastError() : exitCode;
  }
  CloseHandle(launched.process);
  return result;
}

WslStageResult WslFileBridge::Stage(
    std::wstring_view distribution,
    std::filesystem::path const& linuxHostSource,
    std::filesystem::path const& targetSource) const noexcept {
  try {
    if (!IsSafeDistributionName(distribution))
      return {std::nullopt, ERROR_INVALID_NAME,
              "elf.wsl.distribution_invalid"};
    if (auto const error = EnsureRunning(distribution); error != 0)
      return {std::nullopt, error, "elf.wsl.distribution_unavailable"};
    auto const loader32Source =
        linuxHostSource.parent_path() / L"upx_killer_elf_so_loader_x86";
    auto const loader64Source =
        linuxHostSource.parent_path() / L"upx_killer_elf_so_loader_x64";
    if (!std::filesystem::is_regular_file(linuxHostSource) ||
        !std::filesystem::is_regular_file(loader32Source) ||
        !std::filesystem::is_regular_file(loader64Source) ||
        !std::filesystem::is_regular_file(targetSource))
      return {std::nullopt, ERROR_FILE_NOT_FOUND, "elf.wsl.host_missing"};
    static std::atomic_uint64_t sequence{};
    auto const id = std::to_wstring(GetCurrentProcessId()) + L"-" +
                    std::to_wstring(GetTickCount64()) + L"-" +
                    std::to_wstring(++sequence);
    auto const linuxRoot = "/tmp/upx-killer/session-" + NarrowAscii(id);
    auto windowsRoot = std::filesystem::path{
        L"\\\\wsl.localhost\\" + std::wstring{distribution} +
        L"\\tmp\\upx-killer\\session-" + id};
    std::error_code error;
    std::filesystem::create_directories(windowsRoot, error);
    if (error)
      return {std::nullopt, static_cast<std::uint32_t>(error.value()),
              "elf.wsl.bridge_create_failed"};
    WslStagedJob job{};
    job.windowsRoot = windowsRoot;
    job.linuxRoot = linuxRoot;
    job.linuxTarget = linuxRoot + "/target.elf";
    job.linuxOutput = linuxRoot + "/output.elf";
    job.linuxHost = linuxRoot + "/upx_killer_elf_host";
    job.linuxLoader32 = linuxRoot + "/upx_killer_elf_so_loader_x86";
    job.linuxLoader64 = linuxRoot + "/upx_killer_elf_so_loader_x64";
    job.ownsRoot_ = true;
    std::filesystem::copy_file(linuxHostSource,
                               windowsRoot / L"upx_killer_elf_host",
                               std::filesystem::copy_options::overwrite_existing,
                               error);
    if (error)
      return {std::nullopt, static_cast<std::uint32_t>(error.value()),
              "elf.wsl.host_stage_failed"};
    std::filesystem::copy_file(
        loader32Source, windowsRoot / L"upx_killer_elf_so_loader_x86",
        std::filesystem::copy_options::overwrite_existing, error);
    if (error)
      return {std::nullopt, static_cast<std::uint32_t>(error.value()),
              "elf.wsl.host_stage_failed"};
    std::filesystem::copy_file(
        loader64Source, windowsRoot / L"upx_killer_elf_so_loader_x64",
        std::filesystem::copy_options::overwrite_existing, error);
    if (error)
      return {std::nullopt, static_cast<std::uint32_t>(error.value()),
              "elf.wsl.host_stage_failed"};
    std::filesystem::copy_file(targetSource, windowsRoot / L"target.elf",
                               std::filesystem::copy_options::overwrite_existing,
                               error);
    if (error)
      return {std::nullopt, static_cast<std::uint32_t>(error.value()),
              "elf.wsl.target_stage_failed"};
    for (auto const& entry :
         std::filesystem::directory_iterator(targetSource.parent_path(), error)) {
      if (error) break;
      if (!entry.is_regular_file() || !IsSharedObject(entry.path())) continue;
      std::filesystem::copy_file(
          entry.path(), windowsRoot / entry.path().filename(),
          std::filesystem::copy_options::overwrite_existing, error);
      if (error)
        return {std::nullopt, static_cast<std::uint32_t>(error.value()),
                "elf.wsl.dependency_stage_failed"};
    }
    return {std::move(job), 0, {}};
  } catch (std::filesystem::filesystem_error const& error) {
    return {std::nullopt, static_cast<std::uint32_t>(error.code().value()),
            "elf.wsl.bridge_failed"};
  } catch (...) {
    return {std::nullopt, ERROR_UNHANDLED_EXCEPTION,
            "elf.wsl.bridge_failed"};
  }
}
}  // namespace upx_killer::engine_host::wsl
