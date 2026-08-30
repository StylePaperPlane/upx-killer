#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"
#include "Tests/Support/EngineHostTestClient.h"

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::optional<pe::PeImageLayout> ParseFile(std::filesystem::path const& path) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) return std::nullopt;
  auto const size = stream.tellg();
  if (size <= 0) return std::nullopt;
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  stream.seekg(0);
  stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  if (!stream) return std::nullopt;
  return pe::PeParser::Parse(bytes).layout;
}

std::filesystem::path HostPath(std::filesystem::path const& testDirectory) {
  auto const repository = testDirectory.parent_path().parent_path().parent_path();
  return repository / L"upx-killer" / L"x64" / L"Release" /
         L"upx-killer" / L"upx_killer_engine_host.exe";
}
}

int RunWow64DebugSessionTests() {
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  wchar_t executablePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
  auto const directory = std::filesystem::path{executablePath}.parent_path();
  auto const fixture = directory / L"upx-killer-engine-fixture-x86.exe";
  auto const layout = ParseFile(fixture);
  expect(layout && layout->format == pe::PeFormat::Pe32 &&
             layout->machine == IMAGE_FILE_MACHINE_I386,
         "Win32 fixture is built beside the x64 test host");
  if (!layout) return failures;

  bool callbackInvoked{};
  auto const result = debugging::WindowsDebugSession::Capture(
      {fixture, layout->format, layout->imageKind, layout->entryPoint, layout->sizeOfImage,
       std::chrono::seconds{10}, false, {}, std::nullopt},
      [&](auto const&, auto const& loaded, RelativeVirtualAddress resolved,
          auto const&) {
        callbackInvoked = loaded.base.value <= UINT32_MAX &&
                          resolved.value == layout->entryPoint.value;
        return EngineError::None;
      });
  if (!result.Succeeded() || !callbackInvoked)
    std::cerr << "WOW64 capture error=" << static_cast<unsigned>(result.error)
              << " native=" << result.nativeError
              << " callback=" << callbackInvoked << '\n';
  expect(result.Succeeded() && callbackInvoked,
         "x64 debug host captures a Win32 target at EIP through WOW64");

  auto const output = directory / L"upx-killer-engine-fixture-x86.dumped.exe";
  upx_killer::contracts::UnpackJobRequest request{};
  request.targetPath = fixture;
  request.outputPath = output;
  request.entryPoint = upx_killer::contracts::EntryPointHint{
      upx_killer::contracts::EntryPointAddressKind::RelativeVirtualAddress,
      layout->entryPoint.value};
  request.timeoutMilliseconds = 15'000;
  auto const unpacked =
      upx_killer::tests::ExecuteThroughEngineHost(HostPath(directory), request);
  if (unpacked.result.outcome != upx_killer::contracts::JobOutcome::Completed)
    std::cerr << "PE32 engine outcome="
              << static_cast<unsigned>(unpacked.result.outcome)
              << " detail=" << unpacked.result.detailCode
              << " native=" << unpacked.result.nativeCode << '\n';
  expect(unpacked.protocolSucceeded &&
             unpacked.result.outcome ==
                 upx_killer::contracts::JobOutcome::Completed &&
             unpacked.result.artifact,
         "PE32 fixture completes the full unpacking pipeline");

  auto const repaired = ParseFile(output);
  expect(repaired && repaired->format == pe::PeFormat::Pe32 &&
             repaired->preferredImageBase == 0x00400000 &&
             repaired->directories[IMAGE_DIRECTORY_ENTRY_IMPORT].address.value != 0 &&
             repaired->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].address.value != 0,
         "PE32 artifact publishes imports and HIGHLOW relocations at the canonical base");
  if (repaired) {
    std::ifstream stream(output, std::ios::binary | std::ios::ate);
    std::vector<std::byte> bytes(static_cast<std::size_t>(stream.tellg()));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
    auto fourth = pe::rebasing::PeFileRebaser::Rebase(
        bytes, *repaired, LoadedAddress{0x30000000});
    bool fourthBaseCaptured{};
    if (fourth.image) {
      auto const fourthResult = debugging::WindowsDebugSession::Capture(
          {output, repaired->format, repaired->imageKind, repaired->entryPoint,
           repaired->sizeOfImage,
           std::chrono::seconds{10}, false, fourth.image->bytes, fourth.image->requiredBase},
          [&](auto const&, auto const& loaded, auto, auto const&) {
            fourthBaseCaptured = loaded.base.value == 0x30000000;
            return EngineError::None;
          });
      expect(fourthResult.Succeeded() && fourthBaseCaptured,
             "Windows loader applies PE32 HIGHLOW relocations at a fourth base");
    } else {
      expect(false, "PE32 artifact can be rebased to a fourth base");
    }
  }
  std::error_code ignored;
  std::filesystem::remove(output, ignored);
  return failures;
}
