#include "Core/PE/Rebasing/PeFileRebaser.h"

#include "Core/PE/Format/PeFormatTraits.h"

#include <Windows.h>

#include <cstring>
#include <limits>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::rebasing;

std::optional<std::size_t> RvaToRaw(PeImageLayout const& layout, std::uint32_t rva,
                                    std::size_t size) noexcept {
  if (rva < layout.sizeOfHeaders)
    return size <= layout.sizeOfHeaders - rva ? std::optional<std::size_t>{rva} : std::nullopt;
  for (auto const& section : layout.sections) {
    if (rva < section.virtualAddress.value) continue;
    auto const delta = static_cast<std::uint64_t>(rva) - section.virtualAddress.value;
    if (delta <= section.rawSize && size <= section.rawSize - delta)
      return static_cast<std::size_t>(section.rawOffset.value + delta);
  }
  return std::nullopt;
}

template <typename T>
bool Read(std::span<std::byte const> bytes, std::size_t offset, T& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  std::memcpy(&value, bytes.data() + offset, sizeof(T));
  return true;
}

template <typename T>
bool Write(std::vector<std::byte>& bytes, std::size_t offset, T const& value) noexcept {
  if (offset > bytes.size() || sizeof(T) > bytes.size() - offset) return false;
  std::memcpy(bytes.data() + offset, &value, sizeof(T));
  return true;
}

template <typename Traits>
PeFileRebaseResult RebaseTyped(std::span<std::byte const> source, PeImageLayout const& layout,
                               LoadedAddress requiredBase) noexcept {
  using Pointer = typename Traits::Pointer;
  using NtHeaders = typename Traits::NtHeaders;

  if (!Traits::AddressFits(requiredBase.value) || !Traits::AddressFits(layout.preferredImageBase) ||
      layout.ntHeaderOffset > source.size() ||
      sizeof(NtHeaders) > source.size() - layout.ntHeaderOffset)
    return {std::nullopt, PeFileRebaseError::InvalidInput};

  auto const& directory = layout.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (directory.address.value == 0 || directory.size < sizeof(IMAGE_BASE_RELOCATION))
    return {std::nullopt, PeFileRebaseError::MissingRelocations};

  RebasedFileImage result{};
  result.bytes.assign(source.begin(), source.end());
  result.requiredBase = requiredBase;
  auto const delta = static_cast<Pointer>(requiredBase.value) -
                     static_cast<Pointer>(layout.preferredImageBase);
  std::uint32_t consumed{};
  while (consumed < directory.size) {
    auto const blockRaw =
        RvaToRaw(layout, directory.address.value + consumed, sizeof(IMAGE_BASE_RELOCATION));
    IMAGE_BASE_RELOCATION block{};
    if (!blockRaw || !Read(source, *blockRaw, block) ||
        block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
        block.SizeOfBlock > directory.size - consumed ||
        ((block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(WORD)) != 0)
      return {std::nullopt, PeFileRebaseError::InvalidRelocationDirectory};

    auto const entryCount =
        (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
    for (std::uint32_t index = 0; index < entryCount; ++index) {
      WORD entry{};
      auto const entryRva = directory.address.value + consumed +
                            static_cast<std::uint32_t>(sizeof(IMAGE_BASE_RELOCATION)) +
                            index * static_cast<std::uint32_t>(sizeof(WORD));
      auto const entryRaw = RvaToRaw(layout, entryRva, sizeof(entry));
      if (!entryRaw || !Read(source, *entryRaw, entry))
        return {std::nullopt, PeFileRebaseError::InvalidRelocationDirectory};
      auto const type = static_cast<WORD>(entry >> 12);
      if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
      if (type != Traits::RelocationType)
        return {std::nullopt, PeFileRebaseError::UnsupportedRelocationType};

      auto const slot64 = static_cast<std::uint64_t>(block.VirtualAddress) + (entry & 0x0fffu);
      if (slot64 > std::numeric_limits<std::uint32_t>::max())
        return {std::nullopt, PeFileRebaseError::InvalidRelocationDirectory};
      auto const slotRva = static_cast<std::uint32_t>(slot64);
      auto const slotRaw = RvaToRaw(layout, slotRva, sizeof(Pointer));
      Pointer value{};
      if (!slotRaw || !Read(source, *slotRaw, value))
        return {std::nullopt, PeFileRebaseError::InvalidRelocationDirectory};

      auto const wideValue = static_cast<std::uint64_t>(value);
      SourceRelocationSlot evidence{{slotRva}, std::nullopt};
      if (wideValue >= layout.preferredImageBase &&
          wideValue - layout.preferredImageBase < layout.sizeOfImage)
        evidence.imageTarget =
            RelativeVirtualAddress{static_cast<std::uint32_t>(wideValue -
                                                               layout.preferredImageBase)};
      result.sourceSlots.push_back(evidence);
      value = static_cast<Pointer>(value + delta);
      if (!Write(result.bytes, *slotRaw, value))
        return {std::nullopt, PeFileRebaseError::InvalidRelocationDirectory};
    }
    consumed += block.SizeOfBlock;
  }
  if (consumed != directory.size)
    return {std::nullopt, PeFileRebaseError::InvalidRelocationDirectory};

  auto* nt = reinterpret_cast<NtHeaders*>(result.bytes.data() + layout.ntHeaderOffset);
  nt->OptionalHeader.ImageBase = static_cast<Pointer>(requiredBase.value);
  nt->OptionalHeader.DllCharacteristics &= static_cast<WORD>(
      ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
  nt->OptionalHeader.CheckSum = 0;
  return {std::move(result), PeFileRebaseError::None};
}
}

namespace upx_killer::engine::pe::rebasing {
PeFileRebaseResult PeFileRebaser::Rebase(std::span<std::byte const> source,
                                         PeImageLayout const& layout,
                                         LoadedAddress requiredBase) noexcept {
  try {
    if (source.empty() || requiredBase.value == 0 || (requiredBase.value & 0xffffu) != 0 ||
        layout.preferredImageBase == 0)
      return {std::nullopt, PeFileRebaseError::InvalidInput};
    return layout.format == PeFormat::Pe32
               ? RebaseTyped<format::Pe32Traits>(source, layout, requiredBase)
               : RebaseTyped<format::Pe64Traits>(source, layout, requiredBase);
  } catch (...) {
    return {std::nullopt, PeFileRebaseError::InvalidInput};
  }
}
}
