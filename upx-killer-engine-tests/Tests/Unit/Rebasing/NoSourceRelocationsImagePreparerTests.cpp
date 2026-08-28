#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/NoSourceRelocations/NoSourceRelocationsImagePreparer.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace
{
    using namespace upx_killer::engine;

    std::vector<std::byte> MakePeWithoutSourceRelocations()
    {
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
        nt->OptionalHeader.ImageBase = 0x400000ull;
        nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
        nt->OptionalHeader.SectionAlignment = 0x1000;
        nt->OptionalHeader.FileAlignment = 0x200;
        nt->OptionalHeader.SizeOfImage = 0x2000;
        nt->OptionalHeader.SizeOfHeaders = 0x200;
        nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt->OptionalHeader.DllCharacteristics =
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA |
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
        nt->OptionalHeader.CheckSum = 0x12345678;

        auto* section = IMAGE_FIRST_SECTION(nt);
        std::memcpy(section->Name, "UPX1", 4);
        section->Misc.VirtualSize = 0x200;
        section->VirtualAddress = 0x1000;
        section->SizeOfRawData = 0x200;
        section->PointerToRawData = 0x200;
        section->Characteristics =
            IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        return bytes;
    }
}

int RunNoSourceRelocationsImagePreparerTests()
{
    using namespace upx_killer::engine;
    int failures{};
    auto expect = [&](bool condition, std::string_view message)
    {
        if (!condition)
        {
            ++failures;
            std::cerr << "FAILED: " << message << '\n';
        }
    };

    auto source = MakePeWithoutSourceRelocations();
    auto parsed = pe::PeParser::Parse(source);
    expect(parsed.Succeeded(), "no-source-relocations fixture parses");
    if (!parsed.layout) return failures;

    auto prepared = pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
        source, *parsed.layout, LoadedAddress{ 0x180000000ull });
    expect(prepared.Succeeded(), "missing source relocations use the dedicated staging path");
    if (prepared.image)
    {
        auto expected = source;
        auto* expectedNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            expected.data() + parsed.layout->ntHeaderOffset);
        expectedNt->OptionalHeader.ImageBase = 0x180000000ull;
        expectedNt->OptionalHeader.DllCharacteristics &= static_cast<WORD>(~(
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
            IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA));
        expect(prepared.image->bytes == expected,
            "no-source staging changes only loader-placement metadata");
        expect(prepared.image->requiredBase.value == 0x180000000ull,
            "no-source staging records the required base");
    }

    auto inconsistent = source;
    auto* inconsistentNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        inconsistent.data() + parsed.layout->ntHeaderOffset);
    inconsistentNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0x1000, 0 };
    auto inconsistentLayout = pe::PeParser::Parse(inconsistent);
    auto rejected = pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
        inconsistent, *inconsistentLayout.layout, LoadedAddress{ 0x180000000ull });
    expect(rejected.error == pe::rebasing::NoSourceRelocationsPreparationError::SourceRelocationsPresent,
        "the no-source path rejects non-empty or inconsistent source relocation metadata");
    return failures;
}
