#include "Core/PE/Rebasing/NoSourceRelocations/NoSourceRelocationsImagePreparer.h"

#include "Core/PE/Format/PeFormatTraits.h"
#include "Core/PE/Rebasing/NoSourceRelocations/UpxPe32StubAddressingRebaser.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>

namespace {
using namespace upx_killer::engine;
using namespace upx_killer::engine::pe;
using namespace upx_killer::engine::pe::rebasing;

template <typename Traits>
NoSourceRelocationsPreparationResult PrepareTyped(std::span<std::byte const> source,
                                                   PeImageLayout const& layout,
                                                   LoadedAddress requiredBase) noexcept {
  using NtHeaders = typename Traits::NtHeaders;
  using Pointer = typename Traits::Pointer;
  if (!Traits::AddressFits(requiredBase.value) || layout.ntHeaderOffset > source.size() ||
      sizeof(NtHeaders) > source.size() - layout.ntHeaderOffset)
    return {std::nullopt, NoSourceRelocationsPreparationError::InvalidInput};

  NoSourceRelocationsImage result{
      std::vector<std::byte>{source.begin(), source.end()},
      requiredBase,
      {},
  };
  auto* nt = reinterpret_cast<NtHeaders*>(result.bytes.data() + layout.ntHeaderOffset);
  nt->OptionalHeader.ImageBase = static_cast<Pointer>(requiredBase.value);
  nt->OptionalHeader.DllCharacteristics &= static_cast<WORD>(
      ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
  if constexpr (Traits::Format == PeFormat::Pe32) {
    auto const stubRebase = detail::UpxPe32StubAddressingRebaser::Rebase(
        result.bytes, layout, requiredBase);
    if (stubRebase.status == detail::UpxPe32StubAddressingRebaseStatus::Invalid)
      return {std::nullopt, NoSourceRelocationsPreparationError::InvalidInput};
    if (stubRebase.status == detail::UpxPe32StubAddressingRebaseStatus::Applied) {
      if (!stubRebase.patchedLocation || !stubRebase.imageTarget)
        return {std::nullopt, NoSourceRelocationsPreparationError::InvalidInput};
      result.stagingOnlySlots.push_back(
          {*stubRebase.patchedLocation, *stubRebase.imageTarget});
    }
  }
  return {std::move(result), NoSourceRelocationsPreparationError::None};
}
}

namespace upx_killer::engine::pe::rebasing {
NoSourceRelocationsPreparationResult NoSourceRelocationsImagePreparer::Prepare(
    std::span<std::byte const> source, PeImageLayout const& layout,
    LoadedAddress requiredBase) noexcept {
  try {
    if (source.empty() || requiredBase.value == 0 || (requiredBase.value & 0xffffu) != 0 ||
        layout.preferredImageBase == 0)
      return {std::nullopt, NoSourceRelocationsPreparationError::InvalidInput};
    auto const& directory = layout.directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (directory.address.value != 0 || directory.size != 0)
      return {std::nullopt, NoSourceRelocationsPreparationError::SourceRelocationsPresent};
    return layout.format == PeFormat::Pe32
               ? PrepareTyped<format::Pe32Traits>(source, layout, requiredBase)
               : PrepareTyped<format::Pe64Traits>(source, layout, requiredBase);
  } catch (...) {
    return {std::nullopt, NoSourceRelocationsPreparationError::InvalidInput};
  }
}
}
