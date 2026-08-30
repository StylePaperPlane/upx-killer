#include "Core/PE/Rebasing/NoSourceRelocations/UpxPe32StubAddressingRebaser.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::rebasing::detail;

constexpr std::size_t PrologueSize = 12;
constexpr std::size_t SourceImmediateOffset = 2;
constexpr std::size_t DestinationDisplacementOffset = 8;

std::optional<std::size_t> RawOffsetForRva(PeImageLayout const& layout,
                                           RelativeVirtualAddress rva,
                                           std::size_t size) noexcept {
  if (rva.value < layout.sizeOfHeaders && size <= layout.sizeOfHeaders - rva.value)
    return static_cast<std::size_t>(rva.value);
  for (auto const& section : layout.sections) {
    if (rva.value < section.virtualAddress.value) continue;
    auto const delta = rva.value - section.virtualAddress.value;
    if (delta <= section.rawSize && size <= section.rawSize - delta)
      return static_cast<std::size_t>(section.rawOffset.value) + delta;
  }
  return std::nullopt;
}

PeSection const* SectionContaining(PeImageLayout const& layout,
                                   std::uint32_t rva) noexcept {
  auto const found = std::find_if(
      layout.sections.begin(), layout.sections.end(), [&](PeSection const& section) {
        auto const extent = std::max(section.virtualSize, section.rawSize);
        return rva >= section.virtualAddress.value &&
               rva - section.virtualAddress.value < extent;
      });
  return found == layout.sections.end() ? nullptr : &*found;
}
}

namespace upx_killer::engine::pe::rebasing::detail {
UpxPe32StubAddressingRebaseResult UpxPe32StubAddressingRebaser::Rebase(
    std::span<std::byte> stagedImage, PeImageLayout const& layout,
    LoadedAddress requiredBase) noexcept {
  try {
    if (layout.format != PeFormat::Pe32)
      return {UpxPe32StubAddressingRebaseStatus::NotApplicable};
    auto const entryOffset = RawOffsetForRva(layout, layout.entryPoint, PrologueSize);
    if (!entryOffset || *entryOffset > stagedImage.size() ||
        PrologueSize > stagedImage.size() - *entryOffset)
      return {UpxPe32StubAddressingRebaseStatus::Invalid};

    auto const* prologue = stagedImage.data() + *entryOffset;
    if (prologue[0] != std::byte{0x60} || prologue[1] != std::byte{0xBE} ||
        prologue[6] != std::byte{0x8D} || prologue[7] != std::byte{0xBE})
      return {UpxPe32StubAddressingRebaseStatus::NotApplicable};

    std::uint32_t sourceAddress{};
    std::int32_t destinationDisplacement{};
    std::memcpy(&sourceAddress, prologue + SourceImmediateOffset, sizeof(sourceAddress));
    std::memcpy(&destinationDisplacement,
                prologue + DestinationDisplacementOffset,
                sizeof(destinationDisplacement));

    auto const* packedSection = SectionContaining(layout, layout.entryPoint.value);
    if (!packedSection || layout.preferredImageBase > std::numeric_limits<std::uint32_t>::max())
      return {UpxPe32StubAddressingRebaseStatus::Invalid};
    auto const expectedSource = layout.preferredImageBase + packedSection->virtualAddress.value;
    if (expectedSource > std::numeric_limits<std::uint32_t>::max() ||
        sourceAddress != expectedSource)
      return {UpxPe32StubAddressingRebaseStatus::Invalid};

    auto const destinationAddress = static_cast<std::int64_t>(sourceAddress) +
                                    static_cast<std::int64_t>(destinationDisplacement);
    if (destinationAddress < static_cast<std::int64_t>(layout.preferredImageBase) ||
        destinationAddress - static_cast<std::int64_t>(layout.preferredImageBase) >=
            layout.sizeOfImage)
      return {UpxPe32StubAddressingRebaseStatus::Invalid};
    auto const destinationRva = static_cast<std::uint32_t>(
        destinationAddress - static_cast<std::int64_t>(layout.preferredImageBase));
    auto const* destinationSection = SectionContaining(layout, destinationRva);
    if (!destinationSection || destinationSection == packedSection ||
        destinationRva != destinationSection->virtualAddress.value ||
        destinationSection->rawSize != 0 || destinationSection->virtualSize == 0)
      return {UpxPe32StubAddressingRebaseStatus::Invalid};

    auto const stagedSource = requiredBase.value + packedSection->virtualAddress.value;
    if (stagedSource > std::numeric_limits<std::uint32_t>::max())
      return {UpxPe32StubAddressingRebaseStatus::Invalid};
    auto const stagedSource32 = static_cast<std::uint32_t>(stagedSource);
    std::memcpy(stagedImage.data() + *entryOffset + SourceImmediateOffset,
                &stagedSource32, sizeof(stagedSource32));
    return {
        UpxPe32StubAddressingRebaseStatus::Applied,
        RelativeVirtualAddress{layout.entryPoint.value +
                               static_cast<std::uint32_t>(SourceImmediateOffset)},
        RelativeVirtualAddress{packedSection->virtualAddress.value},
    };
  } catch (...) {
    return {UpxPe32StubAddressingRebaseStatus::Invalid};
  }
}
}
