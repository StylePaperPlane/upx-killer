#include "Application/PE/Preparation/PeTargetProbe.h"

#include "Core/PE/Parsing/PeParser.h"

namespace {
using namespace upx_killer;

std::string ParseDetail(engine::pe::PeError error) {
  switch (error) {
    case engine::pe::PeError::UnsupportedArchitecture:
      return "pe.architecture.unsupported";
    case engine::pe::PeError::UnsupportedImageKind:
      return "pe.image_kind.unsupported";
    default:
      return "pe.target.invalid";
  }
}
}

namespace upx_killer::engine::application::pe_preparation {
contracts::BackendProbeResult PeTargetProbe::Execute(
    contracts::UnpackJobRequest const& request) const noexcept {
  auto source = sourceReader_.Read(request.targetPath, request.maximumImageSize);
  if (!source.source || source.source->bytes.size() < 2) return {};
  auto const* signature = reinterpret_cast<unsigned char const*>(
      source.source->bytes.data());
  if (signature[0] != 'M' || signature[1] != 'Z') return {};
  auto parsed = pe::PeParser::Parse(source.source->bytes);
  if (!parsed.layout)
    return {true, false, std::nullopt, ParseDetail(parsed.error)};
  auto descriptor = PeBackendCapabilities::Describe(*parsed.layout);
  auto const supported = capabilities_.Supports(descriptor);
  return {true, supported, descriptor,
          supported ? std::string{} : "pe.target.unsupported"};
}
}
