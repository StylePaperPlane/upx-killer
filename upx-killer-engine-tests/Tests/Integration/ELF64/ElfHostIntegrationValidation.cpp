#include "Tests/Support/EngineHostTestClient.h"

#include <Windows.h>

#include <filesystem>
#include <iostream>

int ValidateElfTargetThroughHost(std::filesystem::path const& target,
                                 std::filesystem::path const& output) {
  using namespace upx_killer;

  wchar_t executablePath[MAX_PATH]{};
  if (GetModuleFileNameW(nullptr, executablePath, MAX_PATH) == 0) return 2;
  auto const testDirectory =
      std::filesystem::path{executablePath}.parent_path();
  auto const repository =
      testDirectory.parent_path().parent_path().parent_path();
  auto const host = repository / L"upx-killer" / L"x64" / L"Release" /
                    L"upx-killer" / L"upx_killer_engine_host.exe";

  contracts::UnpackJobRequest request{};
  request.targetPath = target;
  request.outputPath = output;
  request.timeoutMilliseconds = 60'000;
  auto execution = tests::ExecuteThroughEngineHost(host, request);
  std::cout << "protocol=" << execution.protocolSucceeded
            << " outcome=" << static_cast<int>(execution.result.outcome)
            << " category=" << static_cast<int>(execution.result.category)
            << " native=" << execution.result.nativeCode
            << " detail=" << execution.result.detailCode << '\n';
  if (execution.result.artifact) {
    std::cout << "artifact=" << execution.result.artifact->path.string()
              << " loaderVerified="
              << execution.result.artifact->loaderVerified << '\n';
  }
  return execution.protocolSucceeded &&
                 execution.result.outcome == contracts::JobOutcome::Completed &&
                 execution.result.category == contracts::ErrorCategory::None &&
                 execution.result.nativeCode == 0 && execution.result.artifact &&
                 execution.result.artifact->loaderVerified
             ? 0
             : 1;
}
