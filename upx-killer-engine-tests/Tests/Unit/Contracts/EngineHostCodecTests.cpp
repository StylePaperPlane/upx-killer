#include "Protocol/EngineHost/EngineHostCodec.h"

#include <cstring>
#include <iostream>

namespace {
using namespace upx_killer::contracts;
using namespace upx_killer::contracts::protocol;

int failures{};

void Expect(bool value, char const* message) {
  if (!value) {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

std::optional<EngineHostMessage> RoundTrip(EngineHostMessage const& message) {
  auto frame = EngineHostCodec::Encode(message);
  if (!frame || frame->size() < FrameHeaderSize) return std::nullopt;
  auto header = EngineHostCodec::DecodeHeader(
      std::span<std::byte const>{frame->data(), FrameHeaderSize});
  if (!header) return std::nullopt;
  return EngineHostCodec::DecodePayload(
      *header, std::span<std::byte const>{frame->data() + FrameHeaderSize,
                                         frame->size() - FrameHeaderSize});
}
}

int RunEngineHostCodecTests() {
  auto query = RoundTrip(QueryCapabilitiesMessage{});
  Expect(query && std::holds_alternative<QueryCapabilitiesMessage>(*query),
         "capability queries round-trip through protocol v6");

  CapabilitiesMessage capabilities{{
      {"pe.windows.upx",
       {{BinaryFamily::Pe, BinaryClass::Bits32, CpuArchitecture::X86,
         ImageKind::Executable},
        {BinaryFamily::Pe, BinaryClass::Bits32, CpuArchitecture::X86,
         ImageKind::SharedLibrary}}},
  }};
  auto capabilityRoundTrip = RoundTrip(capabilities);
  auto const* decodedCapabilities =
      capabilityRoundTrip
          ? std::get_if<CapabilitiesMessage>(&*capabilityRoundTrip)
          : nullptr;
  Expect(decodedCapabilities && decodedCapabilities->manifests.size() == 1 &&
             decodedCapabilities->manifests[0].capabilities.size() == 2,
         "backend manifests preserve explicit target descriptors");

  ExecuteJobMessage execute{};
  execute.request.targetPath = L"C:\\测试\\输入.exe";
  execute.request.outputPath = L"C:\\测试\\输出.dumped.exe";
  execute.request.entryPoint =
      EntryPointHint{EntryPointAddressKind::RelativeVirtualAddress, 0x1234};
  execute.request.timeoutMilliseconds = 4321;
  execute.request.maximumImageSize = 0x123456789ull;
  execute.request.retainFailedOutput = true;
  auto executeRoundTrip = RoundTrip(execute);
  auto const* decodedExecute =
      executeRoundTrip ? std::get_if<ExecuteJobMessage>(&*executeRoundTrip) : nullptr;
  Expect(decodedExecute && decodedExecute->request.targetPath == execute.request.targetPath &&
             decodedExecute->request.outputPath == execute.request.outputPath &&
             decodedExecute->request.entryPoint &&
             decodedExecute->request.entryPoint->value == 0x1234 &&
             decodedExecute->request.maximumImageSize == 0x123456789ull &&
             decodedExecute->request.retainFailedOutput,
         "UTF-8 job paths and bounded request fields round-trip");

  ResultMessage result{};
  result.result.outcome = JobOutcome::Completed;
  result.result.category = ErrorCategory::None;
  result.result.detailCode = "pe.completed";
  result.result.artifact = JobArtifact{
      L"C:\\测试\\输出.dumped.exe", ArtifactQuality::Complete, true,
      {"warning.one"}};
  auto resultRoundTrip = RoundTrip(result);
  auto const* decodedResult =
      resultRoundTrip ? std::get_if<ResultMessage>(&*resultRoundTrip) : nullptr;
  Expect(decodedResult && decodedResult->result.artifact &&
             decodedResult->result.artifact->warnings.size() == 1 &&
             decodedResult->result.artifact->loaderVerified,
         "job results and artifacts round-trip");

  auto frame = EngineHostCodec::Encode(QueryCapabilitiesMessage{});
  Expect(frame.has_value(), "a valid query frame is encoded");
  if (frame) {
    auto badVersion = *frame;
    std::uint32_t version = 99;
    std::memcpy(badVersion.data() + 4, &version, sizeof(version));
    Expect(!EngineHostCodec::DecodeHeader(
               std::span<std::byte const>{badVersion.data(), FrameHeaderSize}),
           "protocol version mismatches are rejected");

    auto unknownType = *frame;
    std::uint32_t type = 0xDEADBEEF;
    std::memcpy(unknownType.data() + 8, &type, sizeof(type));
    auto header = EngineHostCodec::DecodeHeader(
        std::span<std::byte const>{unknownType.data(), FrameHeaderSize});
    Expect(header && !EngineHostCodec::DecodePayload(*header, {}),
           "unknown wire message codes are rejected");

    Expect(!EngineHostCodec::DecodeHeader(
               std::span<std::byte const>{frame->data(), FrameHeaderSize - 1}),
           "truncated frame headers are rejected");
  }
  return failures;
}
