#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"
#include "Tests/Support/EngineHostTestClient.h"

#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::filesystem::path HostPath(std::filesystem::path const& testDirectory) {
  auto const repository = testDirectory.parent_path().parent_path().parent_path();
  return repository / L"upx-killer" / L"x64" / L"Release" /
         L"upx-killer" / L"upx_killer_engine_host.exe";
}

std::vector<std::byte> ReadAll(std::filesystem::path const& path) {
  std::ifstream stream(path, std::ios::binary | std::ios::ate);
  if (!stream) return {};
  auto const length = stream.tellg();
  if (length <= 0) return {};
  std::vector<std::byte> bytes(static_cast<std::size_t>(length));
  stream.seekg(0);
  stream.read(reinterpret_cast<char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
  return stream ? std::move(bytes) : std::vector<std::byte>{};
}
}

int RunHostIntegrationTests() {
  using namespace upx_killer;
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
  auto const fixture = directory / L"upx-killer-engine-fixture.exe";
  auto const output = directory / L"fixture.host.dumped.exe";
  auto bytes = ReadAll(fixture);
  auto parsed = engine::pe::PeParser::Parse(bytes);
  expect(parsed.layout.has_value(), "host fixture parses");
  if (!parsed.layout) return failures;

  contracts::UnpackJobRequest request{};
  request.targetPath = fixture;
  request.outputPath = output;
  request.entryPoint = contracts::EntryPointHint{
      contracts::EntryPointAddressKind::RelativeVirtualAddress,
      parsed.layout->entryPoint.value};
  request.timeoutMilliseconds = 10'000;
  auto execution = tests::ExecuteThroughEngineHost(HostPath(directory), request);
  expect(execution.protocolSucceeded &&
             execution.result.outcome == contracts::JobOutcome::Completed &&
             execution.result.category == contracts::ErrorCategory::None &&
             execution.result.nativeCode == 0 && execution.result.artifact &&
             execution.result.artifact->loaderVerified,
         "engine host returns a validated completed artifact");

  auto repairedBytes = ReadAll(output);
  auto repaired = engine::pe::PeParser::Parse(repairedBytes);
  expect(repaired.layout &&
             repaired.layout->preferredImageBase == 0x140000000ull &&
             repaired.layout
                     ->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                     .address.value != 0,
         "captured artifact publishes a low preferred base and relocations");
  if (repaired.layout) {
    auto rebased = engine::pe::rebasing::PeFileRebaser::Rebase(
        repairedBytes, *repaired.layout,
        engine::LoadedAddress{0x200000000ull});
    expect(rebased.Succeeded(),
           "repaired artifact applies its own relocation table");
    if (rebased.image) {
      auto fourth = engine::debugging::WindowsDebugSession::Capture(
          {output, repaired.layout->format, repaired.layout->imageKind,
           repaired.layout->entryPoint, repaired.layout->sizeOfImage,
           std::chrono::seconds{10}, false, rebased.image->bytes,
           rebased.image->requiredBase},
          [](auto const&, auto const& loaded, auto, auto const&) {
            return loaded.base.value == 0x200000000ull;
          });
      expect(fourth.Succeeded(),
             "repaired artifact reaches OEP at a fourth controlled base");
    }
  }

  std::optional<std::size_t> entryRaw;
  for (auto const& section : parsed.layout->sections) {
    if (parsed.layout->entryPoint.value >= section.virtualAddress.value &&
        parsed.layout->entryPoint.value - section.virtualAddress.value < section.rawSize) {
      entryRaw = section.rawOffset.value +
                 parsed.layout->entryPoint.value - section.virtualAddress.value;
      break;
    }
  }
  expect(entryRaw && *entryRaw + 2 <= bytes.size(),
         "debugger exit fixture has a file-backed entry point");
  if (entryRaw && *entryRaw + 2 <= bytes.size()) {
    auto runBeforeCandidate = [&](std::byte first, std::byte second) {
      auto staged = bytes;
      staged[*entryRaw] = first;
      staged[*entryRaw + 1] = second;
      engine::pe::oep::OepDiscoveryPlan discovery{};
      discovery.packedEntryPoint = parsed.layout->entryPoint;
      discovery.candidates.push_back({
          engine::pe::oep::OepTransferKind::DirectJump,
          {parsed.layout->entryPoint.value + 0x20},
          {parsed.layout->entryPoint.value + 0x40},
          {parsed.layout->entryPoint.value + 0x40}});
      return engine::debugging::WindowsDebugSession::Capture(
          {fixture, parsed.layout->format, parsed.layout->imageKind,
           std::move(discovery), parsed.layout->sizeOfImage,
           std::chrono::seconds{10}, false, staged,
           std::nullopt},
          [](auto const&, auto const&, auto, auto const&) { return false; });
    };
    auto cleanExit = runBeforeCandidate(bytes[*entryRaw], bytes[*entryRaw + 1]);
    expect(cleanExit.error == engine::debugging::DebugSessionError::EntryPointNotFound,
           "normal exit before a candidate remains an OEP evidence failure");
    auto crash = runBeforeCandidate(std::byte{0x0f}, std::byte{0x0b});
    expect(crash.error == engine::debugging::DebugSessionError::TargetExited &&
               crash.nativeError == EXCEPTION_ILLEGAL_INSTRUCTION,
           "unhandled target exception is not reported as missing OEP");
  }
  std::error_code ignored;
  std::filesystem::remove(output, ignored);
  return failures;
}
