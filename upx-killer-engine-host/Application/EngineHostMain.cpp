#include "Application/Unpacking/UnpackEngine.h"
#include "Protocol/EngineHost/EngineHostProtocol.h"

#include <Windows.h>

int wmain() {
  upx_killer::engine::UnpackRequest request{};
  auto const input = GetStdHandle(STD_INPUT_HANDLE);
  auto const output = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!upx_killer::engine::protocol::ReadRequest(input, request)) return 2;
  auto const result = upx_killer::engine::application::UnpackEngine::Execute(
      request, [&](upx_killer::engine::EngineStage stage) {
        (void)upx_killer::engine::protocol::WriteProgress(output, stage);
      });
  return upx_killer::engine::protocol::WriteResult(output, result) ? 0 : 3;
}
