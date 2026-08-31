#include "pch.h"
#include "Infrastructure/WSL/Discovery/WslDistributionCatalog.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <sstream>

namespace {
std::vector<std::byte> RunListCommand() {
  SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
  HANDLE readRaw{}, writeRaw{};
  if (!CreatePipe(&readRaw, &writeRaw, &security, 0)) return {};
  auto closeHandles = [&] {
    if (readRaw) CloseHandle(readRaw);
    if (writeRaw) CloseHandle(writeRaw);
  };
  if (!SetHandleInformation(readRaw, HANDLE_FLAG_INHERIT, 0)) {
    closeHandles();
    return {};
  }
  STARTUPINFOW startup{sizeof(startup)};
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  startup.hStdOutput = writeRaw;
  startup.hStdError = writeRaw;
  PROCESS_INFORMATION process{};
  std::array<wchar_t, MAX_PATH> systemDirectory{};
  auto const length = GetSystemDirectoryW(systemDirectory.data(),
                                          static_cast<UINT>(systemDirectory.size()));
  if (length == 0 || length >= systemDirectory.size()) {
    closeHandles();
    return {};
  }
  auto wslPath = std::filesystem::path{systemDirectory.data()} / L"wsl.exe";
  std::wstring command = L"\"" + wslPath.wstring() + L"\" --list --verbose";
  if (!CreateProcessW(wslPath.c_str(), command.data(), nullptr, nullptr, TRUE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
    closeHandles();
    return {};
  }
  CloseHandle(writeRaw);
  writeRaw = nullptr;
  CloseHandle(process.hThread);
  auto const wait = WaitForSingleObject(process.hProcess, 10'000);
  if (wait != WAIT_OBJECT_0) {
    TerminateProcess(process.hProcess, ERROR_TIMEOUT);
    (void)WaitForSingleObject(process.hProcess, 5000);
    CloseHandle(process.hProcess);
    CloseHandle(readRaw);
    return {};
  }
  DWORD exitCode{};
  if (!GetExitCodeProcess(process.hProcess, &exitCode) || exitCode != 0) {
    CloseHandle(process.hProcess);
    CloseHandle(readRaw);
    return {};
  }
  CloseHandle(process.hProcess);
  std::vector<std::byte> bytes;
  std::array<std::byte, 4096> buffer{};
  DWORD read{};
  while (ReadFile(readRaw, buffer.data(), static_cast<DWORD>(buffer.size()),
                  &read, nullptr) && read != 0)
    bytes.insert(bytes.end(), buffer.begin(), buffer.begin() + read);
  CloseHandle(readRaw);
  return bytes;
}

std::wstring Decode(std::vector<std::byte> const& bytes) {
  if (bytes.empty()) return {};
  auto const likelyUtf16 = bytes.size() >= 2 && bytes[1] == std::byte{0};
  if (likelyUtf16) {
    auto const count = bytes.size() / sizeof(wchar_t);
    auto const* characters = reinterpret_cast<wchar_t const*>(bytes.data());
    return {characters, characters + count};
  }
  auto const needed = MultiByteToWideChar(
      CP_UTF8, 0, reinterpret_cast<char const*>(bytes.data()),
      static_cast<int>(bytes.size()), nullptr, 0);
  if (needed <= 0) return {};
  std::wstring result(static_cast<std::size_t>(needed), L'\0');
  MultiByteToWideChar(CP_UTF8, 0,
                      reinterpret_cast<char const*>(bytes.data()),
                      static_cast<int>(bytes.size()), result.data(), needed);
  return result;
}
}

namespace upx_killer::infrastructure {
std::vector<application::WslDistributionInfo>
WslDistributionCatalog::List() const noexcept {
  try {
    std::vector<application::WslDistributionInfo> result;
    std::wistringstream lines{Decode(RunListCommand())};
    std::wstring line;
    while (std::getline(lines, line)) {
      line.erase(std::remove(line.begin(), line.end(), L'\r'), line.end());
      if (line.empty() || line.find(L"NAME") != std::wstring::npos) continue;
      std::wistringstream fields{line};
      std::wstring first, name, state;
      unsigned version{};
      if (!(fields >> first)) continue;
      auto const isDefault = first == L"*";
      if (isDefault) {
        if (!(fields >> name >> state >> version)) continue;
      } else {
        name = std::move(first);
        if (!(fields >> state >> version)) continue;
      }
      if (version == 2)
        result.push_back({std::move(name), isDefault, true});
    }
    std::stable_sort(result.begin(), result.end(), [](auto const& left,
                                                      auto const& right) {
      return left.isDefault && !right.isDefault;
    });
    return result;
  } catch (...) {
    return {};
  }
}
}  // namespace upx_killer::infrastructure
