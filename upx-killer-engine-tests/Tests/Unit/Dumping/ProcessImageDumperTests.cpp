#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/Parsing/PeParser.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {
using namespace upx_killer::engine;

std::vector<std::byte> MakeImage() {
  std::vector<std::byte> bytes(0x400);
  auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
  dos->e_magic = IMAGE_DOS_SIGNATURE;
  dos->e_lfanew = 0x80;
  auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + 0x80);
  nt->Signature = IMAGE_NT_SIGNATURE;
  nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
  nt->FileHeader.NumberOfSections = 1;
  nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
  nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt->OptionalHeader.ImageBase = 0x140000000ull;
  nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  nt->OptionalHeader.SectionAlignment = 0x1000;
  nt->OptionalHeader.FileAlignment = 0x200;
  nt->OptionalHeader.SizeOfImage = 0x2000;
  nt->OptionalHeader.SizeOfHeaders = 0x200;
  nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
  auto* section = IMAGE_FIRST_SECTION(nt);
  std::memcpy(section->Name, ".text", 5);
  section->Misc.VirtualSize = 0x100;
  section->VirtualAddress = 0x1000;
  section->SizeOfRawData = 0x200;
  section->PointerToRawData = 0x200;
  section->Characteristics =
      IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
  return bytes;
}

class MemoryReader final : public dumping::IRemoteMemoryReader {
 public:
  explicit MemoryReader(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}
  dumping::MemoryRegion Query(LoadedAddress address) const override {
    return {address, static_cast<std::uint64_t>(bytes_.size()), true};
  }
  std::size_t Read(LoadedAddress address,
                   std::span<std::byte> destination) const override {
    auto const offset = static_cast<std::size_t>(address.value - Base);
    if (offset >= bytes_.size()) return 0;
    auto const count = std::min(destination.size(), bytes_.size() - offset);
    std::copy_n(bytes_.begin() + offset, count, destination.begin());
    return count;
  }
  static constexpr std::uint64_t Base = 0x180000000ull;

 private:
  std::vector<std::byte> bytes_;
};
}

int RunDumperTests() {
  using namespace upx_killer::engine;
  int failures{};
  auto file = MakeImage();
  auto parsed = pe::PeParser::Parse(file);
  std::vector<std::byte> memory(0x2000);
  std::copy_n(file.begin(), 0x200, memory.begin());
  memory[0x1000] = std::byte{0xC3};
  MemoryReader reader(std::move(memory));
  auto result = dumping::ProcessImageDumper::Dump(
      reader, {LoadedAddress{MemoryReader::Base}, 0x2000}, *parsed.layout,
      {0x4000});
  if (!result.Succeeded() || !result.image ||
      result.image->bytes[0x1000] != std::byte{0xC3}) {
    ++failures;
    std::cerr << "FAILED: virtual section bytes are captured\n";
  }
  return failures;
}
