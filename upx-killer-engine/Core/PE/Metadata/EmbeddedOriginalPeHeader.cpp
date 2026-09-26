#include "Core/PE/Metadata/EmbeddedOriginalPeHeader.h"

#include <Windows.h>

#include <algorithm>
#include <cstring>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::metadata;

template <typename T>
bool Read(std::span<std::byte const> bytes, std::size_t offset, T& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return true;
}

std::optional<EmbeddedOriginalPeHeader> Parse(
    std::span<std::byte const> dumped, PeImageLayout const& source,
    RelativeVirtualAddress oep, std::size_t offset) noexcept {
  DWORD signature{};
  IMAGE_FILE_HEADER file{};
  if (!Read(dumped, offset, signature) || signature != IMAGE_NT_SIGNATURE ||
      !Read(dumped, offset + sizeof(signature), file) ||
      file.NumberOfSections == 0 || file.NumberOfSections > 96)
    return std::nullopt;
  auto const pe64 = source.format == PeFormat::Pe64;
  if (file.Machine != (pe64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386) ||
      file.SizeOfOptionalHeader !=
          (pe64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32)))
    return std::nullopt;
  auto const optionalOffset = offset + sizeof(signature) + sizeof(file);
  std::uint32_t entry{}, imageSize{};
  IMAGE_DATA_DIRECTORY imports{}, tls{};
  if (pe64) {
    IMAGE_OPTIONAL_HEADER64 optional{};
    if (!Read(dumped, optionalOffset, optional) ||
        optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
      return std::nullopt;
    entry = optional.AddressOfEntryPoint;
    imageSize = optional.SizeOfImage;
    imports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    tls = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  } else {
    IMAGE_OPTIONAL_HEADER32 optional{};
    if (!Read(dumped, optionalOffset, optional) ||
        optional.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
      return std::nullopt;
    entry = optional.AddressOfEntryPoint;
    imageSize = optional.SizeOfImage;
    imports = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    tls = optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  }
  if (entry != oep.value || imageSize == 0 || imageSize > dumped.size() ||
      imports.VirtualAddress == 0 ||
      imports.Size < 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR) ||
      imports.VirtualAddress >= imageSize ||
      imports.Size > imageSize - imports.VirtualAddress)
    return std::nullopt;
  std::uint32_t importDescriptors{};
  bool terminated{};
  for (std::uint32_t index = 0;
       index < std::min<std::uint32_t>(imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR), 4097);
       ++index) {
    IMAGE_IMPORT_DESCRIPTOR descriptor{};
    if (!Read(dumped, imports.VirtualAddress +
                          static_cast<std::size_t>(index) * sizeof(descriptor), descriptor))
      return std::nullopt;
    if (descriptor.OriginalFirstThunk == 0 && descriptor.TimeDateStamp == 0 &&
        descriptor.ForwarderChain == 0 && descriptor.Name == 0 &&
        descriptor.FirstThunk == 0) {
      terminated = index != 0;
      break;
    }
    if (descriptor.Name >= imageSize || descriptor.FirstThunk >= imageSize)
      return std::nullopt;
    ++importDescriptors;
  }
  if (!terminated) return std::nullopt;
  auto const sectionOffset = optionalOffset + file.SizeOfOptionalHeader;
  auto const sectionsSize = static_cast<std::size_t>(file.NumberOfSections) *
                            sizeof(IMAGE_SECTION_HEADER);
  if (sectionOffset > dumped.size() || sectionsSize > dumped.size() - sectionOffset)
    return std::nullopt;
  IMAGE_SECTION_HEADER first{};
  if (!Read(dumped, sectionOffset, first) || source.sections.empty() ||
      first.VirtualAddress != source.sections.front().virtualAddress.value ||
      first.Misc.VirtualSize == 0)
    return std::nullopt;
  auto const metadataOffset = sectionOffset + sectionsSize;
  if (metadataOffset > dumped.size() || 8 > dumped.size() - metadataOffset)
    return std::nullopt;
  if ((tls.VirtualAddress == 0) != (tls.Size == 0) ||
      (tls.VirtualAddress != 0 &&
       (tls.VirtualAddress >= imageSize || tls.Size > imageSize - tls.VirtualAddress)))
    return std::nullopt;
  return EmbeddedOriginalPeHeader{
      metadataOffset, first.VirtualAddress, imageSize,
      importDescriptors,
      {RelativeVirtualAddress{tls.VirtualAddress}, tls.Size}};
}
}

namespace upx_killer::engine::pe::metadata {
std::optional<EmbeddedOriginalPeHeader> FindEmbeddedOriginalPeHeader(
    std::span<std::byte const> dumped, PeImageLayout const& source,
    RelativeVirtualAddress recoveredEntryPoint) noexcept {
  try {
    if (source.entryPoint.value == recoveredEntryPoint.value) return std::nullopt;
    std::optional<EmbeddedOriginalPeHeader> result;
    for (std::size_t offset = 0; offset + sizeof(IMAGE_NT_HEADERS32) < dumped.size(); ++offset) {
      if (dumped[offset] != std::byte{'P'}) continue;
      auto parsed = Parse(dumped, source, recoveredEntryPoint, offset);
      if (!parsed) continue;
      if (result) return std::nullopt;
      result = std::move(parsed);
    }
    return result;
  } catch (...) {
    return std::nullopt;
  }
}
}
