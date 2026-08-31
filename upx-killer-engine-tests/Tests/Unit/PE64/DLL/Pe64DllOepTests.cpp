#include "Core/PE/OepDiscovery/UpxOepLocator.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

pe::PeSection Section(char const* name, std::uint32_t virtualAddress,
                      std::uint32_t virtualSize, std::uint32_t rawOffset,
                      std::uint32_t rawSize, std::uint32_t characteristics) {
  pe::PeSection section{};
  std::memcpy(section.name.data(), name,
              std::min<std::size_t>(std::strlen(name), section.name.size()));
  section.virtualAddress = {virtualAddress};
  section.virtualSize = virtualSize;
  section.rawOffset = {rawOffset};
  section.rawSize = rawSize;
  section.characteristics = characteristics;
  return section;
}

struct Pe64DllStub {
  std::vector<std::byte> bytes = std::vector<std::byte>(0x800);
  pe::PeImageLayout layout{};

  Pe64DllStub() {
    layout.format = pe::PeFormat::Pe64;
    layout.imageKind = pe::PeImageKind::DynamicLibrary;
    layout.entryPoint = {0x2100};
    layout.sizeOfImage = 0x4000;
    layout.sections.push_back(Section("UPX0", 0x1000, 0x1000, 0, 0,
                                     IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE |
                                         IMAGE_SCN_MEM_EXECUTE));
    layout.sections.push_back(Section("UPX1", 0x2000, 0x1000, 0x200, 0x400,
                                     IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ |
                                         IMAGE_SCN_MEM_EXECUTE));
    std::memcpy(bytes.data() + 0x240, "UPX!", 4);
  }

  void WriteRestore(std::size_t offset) {
    constexpr std::array<std::uint8_t, 4> restore{0x5d, 0x5f, 0x5e, 0x5b};
    std::memcpy(bytes.data() + offset, restore.data(), restore.size());
  }
};
}

int RunPe64DllOepTests() {
  int failures{};
  auto expect = [&](bool condition, std::string_view message) {
    if (!condition) {
      ++failures;
      std::cerr << "FAILED: " << message << '\n';
    }
  };

  Pe64DllStub direct;
  auto const tailOffset = std::size_t{0x380};
  direct.WriteRestore(tailOffset);
  direct.bytes[tailOffset + 4] = std::byte{0xe9};
  auto const transferRva = std::uint32_t{0x2184};
  auto const targetRva = std::uint32_t{0x1100};
  auto const displacement = static_cast<std::int32_t>(targetRva - (transferRva + 5));
  std::memcpy(direct.bytes.data() + tailOffset + 5, &displacement,
              sizeof(displacement));
  auto directResult = pe::oep::UpxOepLocator::Analyze(direct.bytes, direct.layout);
  expect(directResult.plan && directResult.plan->candidates.size() == 1 &&
             directResult.plan->candidates.front().kind ==
                 pe::oep::OepTransferKind::DirectJump &&
             directResult.plan->candidates.front().target.value == targetRva,
         "PE64 DLL direct rel32 tail resolves its DllMain OEP");

  Pe64DllStub noEntry;
  noEntry.WriteRestore(tailOffset);
  constexpr std::array<std::uint8_t, 4> returnTrue{0x6a, 0x01, 0x58, 0xc3};
  std::memcpy(noEntry.bytes.data() + tailOffset + 4, returnTrue.data(),
              returnTrue.size());
  auto noEntryResult = pe::oep::UpxOepLocator::Analyze(noEntry.bytes, noEntry.layout);
  expect(noEntryResult.plan && noEntryResult.plan->candidates.size() == 1 &&
             noEntryResult.plan->candidates.front().kind ==
                 pe::oep::OepTransferKind::DllReturn &&
             noEntryResult.plan->candidates.front().target.value == 0 &&
             noEntryResult.plan->candidates.front().transfer.value == 0x2187,
         "PE64 DLL push-one/pop-rax/ret tail resolves a zero OEP");
  return failures;
}
