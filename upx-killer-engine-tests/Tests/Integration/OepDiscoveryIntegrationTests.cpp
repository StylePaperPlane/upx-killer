#include "Application/Unpacking/UnpackEngine.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/PE/Parsing/PeParser.h"
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

int failures{};

void Expect(bool condition, std::string_view message) {
  if (!condition) {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

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
}

int RunOepDiscoveryIntegrationTests() {
  wchar_t currentExecutable[MAX_PATH]{};
  GetModuleFileNameW(nullptr, currentExecutable, MAX_PATH);
  auto const currentDirectory = std::filesystem::path{currentExecutable}.parent_path();
  UnpackRequest ordinaryRequest{};
  ordinaryRequest.targetPath = currentDirectory / L"upx-killer-engine-fixture.exe";
  ordinaryRequest.outputPath = currentDirectory / L"ordinary.auto.dumped.exe";
  auto const ordinaryResult = application::UnpackEngine::Execute(ordinaryRequest, {});
  Expect(ordinaryResult.outcome == EngineOutcome::UnsupportedTarget &&
             ordinaryResult.error == EngineError::UnsupportedPacker,
         "ordinary x64 PE is rejected before automatic debugging starts");
  Expect(!std::filesystem::exists(ordinaryRequest.outputPath),
         "unsupported packer does not leave an artifact");

  std::vector<wchar_t> packedBuffer(32768);
  auto const packedLength = GetEnvironmentVariableW(L"UPX_PACKED_FIXTURE", packedBuffer.data(),
                                                    static_cast<DWORD>(packedBuffer.size()));
  if (packedLength == 0 || packedLength >= packedBuffer.size()) return 0;

  wchar_t executablePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
  auto const testDirectory = std::filesystem::path{executablePath}.parent_path();
  auto const original = testDirectory / L"upx-killer-engine-fixture.exe";
  auto const packed = std::filesystem::path{std::wstring_view{packedBuffer.data(), packedLength}};
  auto const output = testDirectory / L"fixture.auto.dumped.exe";
  auto const originalLayout = ParseFile(original);
  Expect(originalLayout.has_value(), "original fixture parses for automatic OEP comparison");

  UnpackRequest request{};
  request.targetPath = packed;
  request.outputPath = output;
  request.timeoutMilliseconds = 15'000;
  auto const result = application::UnpackEngine::Execute(request, {});
  if (result.outcome != EngineOutcome::Partial) {
    std::cerr << "automatic integration outcome=" << static_cast<unsigned>(result.outcome)
              << " error=" << static_cast<unsigned>(result.error)
              << " native=" << result.nativeError << '\n';
  }
  Expect(result.outcome == EngineOutcome::Partial,
         "official UPX fixture is captured automatically");
  Expect(result.artifact && result.artifact->loaderMappable,
         "automatic artifact passes non-executing mapping");
  auto const repairedLayout = ParseFile(output);
  Expect(repairedLayout.has_value(), "automatic repaired image parses");
  if (originalLayout && repairedLayout) {
    Expect(repairedLayout->entryPoint.value == originalLayout->entryPoint.value,
           "automatic OEP equals the original fixture entry point");
  }
  std::error_code ignored;
  std::filesystem::remove(output, ignored);
  return failures;
}

int AnalyzeAutomaticOepTarget(std::filesystem::path const& target) {
  std::ifstream stream(target, std::ios::binary | std::ios::ate);
  if (!stream) return 2;
  auto const size = stream.tellg();
  if (size <= 0) return 2;
  std::vector<std::byte> bytes(static_cast<std::size_t>(size));
  stream.seekg(0);
  stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  auto parsed = pe::PeParser::Parse(bytes);
  if (!parsed.layout) {
    std::wcout << L"parse_error=" << static_cast<unsigned>(parsed.error) << L'\n';
    return 3;
  }
  auto discovery = pe::oep::UpxOepLocator::Analyze(bytes, *parsed.layout);
  std::wcout << L"discovery_error=" << static_cast<unsigned>(discovery.error) << L'\n';
  std::wcout << L"candidate_count=" << (discovery.plan ? discovery.plan->candidates.size() : 0)
             << L'\n';
  if (discovery.plan) {
    for (auto const& candidate : discovery.plan->candidates) {
      std::wcout << L"transfer_rva=0x" << std::hex << candidate.transfer.value << L" target_rva=0x"
                 << candidate.target.value << std::dec << L'\n';
    }
  }
  return discovery.plan ? 0 : 4;
}

int ValidateAutomaticOepTarget(std::filesystem::path const& target) {
  auto const outputDirectory = std::filesystem::temp_directory_path() / L"upx-killer-validation";
  std::error_code error;
  std::filesystem::create_directories(outputDirectory, error);
  if (error) return 5;
  auto const output = outputDirectory / (target.stem().wstring() + L".dumped.exe");
  UnpackRequest request{};
  request.targetPath = target;
  request.outputPath = output;
  request.timeoutMilliseconds = 60'000;
  auto const result = application::UnpackEngine::Execute(request, {});
  std::wcout << L"outcome=" << static_cast<unsigned>(result.outcome) << L'\n';
  std::wcout << L"error=" << static_cast<unsigned>(result.error) << L'\n';
  std::wcout << L"native_error=" << result.nativeError << L'\n';
  if (result.artifact) {
    std::wcout << L"artifact=" << result.artifact->path.wstring() << L'\n';
    std::wcout << L"loader_mappable=" << result.artifact->loaderMappable << L'\n';
  }
  return result.outcome == EngineOutcome::Partial || result.outcome == EngineOutcome::Completed ? 0
                                                                                                : 6;
}

int ValidateAutomaticOepTargetThroughHost(std::filesystem::path const& target) {
  wchar_t executablePath[MAX_PATH]{};
  GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
  auto const testDirectory = std::filesystem::path{executablePath}.parent_path();
  auto const repository = testDirectory.parent_path().parent_path().parent_path();
  auto const host = repository / L"upx-killer" / L"x64" / L"Release" / L"upx-killer" /
                    L"upx_killer_engine_host.exe";
  auto const outputDirectory = std::filesystem::temp_directory_path() / L"upx-killer-validation";
  std::error_code error;
  std::filesystem::create_directories(outputDirectory, error);
  if (error) return 5;

  UnpackRequest request{};
  request.targetPath = target;
  request.outputPath = outputDirectory /
                       (target.stem().wstring() + L".host.dumped" + target.extension().wstring());
  request.retainFailedOutput = true;
  request.timeoutMilliseconds = 60'000;
  auto const execution = tests::ExecuteThroughEngineHost(host, request);
  std::wcout << L"protocol_succeeded=" << execution.protocolSucceeded << L'\n';
  std::wcout << L"outcome=" << static_cast<unsigned>(execution.result.outcome) << L'\n';
  std::wcout << L"error=" << static_cast<unsigned>(execution.result.error) << L'\n';
  std::wcout << L"native_error=" << execution.result.nativeError << L'\n';
  if (execution.result.artifact) {
    std::wcout << L"artifact=" << execution.result.artifact->path.wstring() << L'\n';
    std::wcout << L"loader_mappable=" << execution.result.artifact->loaderMappable << L'\n';
  }
  return execution.protocolSucceeded && (execution.result.outcome == EngineOutcome::Partial ||
                                         execution.result.outcome == EngineOutcome::Completed)
             ? 0
             : 6;
}
