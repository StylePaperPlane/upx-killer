#include "Application/ELF/Preparation/ElfTargetProbe.h"

namespace upx_killer::engine::application::elf_preparation {
contracts::BackendProbeResult ElfTargetProbe::Execute(
    contracts::UnpackJobRequest const& request) const noexcept {
  auto source = reader_.Read(request.targetPath, 1u << 20);
  if (!source.bytes || source.bytes->size() < 4) return {};
  auto const& bytes = *source.bytes;
  if (std::to_integer<std::uint8_t>(bytes[0]) != 0x7f ||
      std::to_integer<std::uint8_t>(bytes[1]) != 'E' ||
      std::to_integer<std::uint8_t>(bytes[2]) != 'L' ||
      std::to_integer<std::uint8_t>(bytes[3]) != 'F')
    return {};
  auto parsed = elf::ElfParser::Parse(bytes);
  if (!parsed.layout)
    return {true, false, std::nullopt, "elf.target.unsupported"};
  auto const descriptor =
      ElfBackendCapabilities::DescriptorFor(*parsed.layout);
  return {true, descriptor.has_value(), descriptor,
          descriptor ? std::string{}
                     : std::string{"elf.target.kind_unsupported"}};
}
}  // namespace upx_killer::engine::application::elf_preparation
