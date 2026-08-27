#include "Core/PE/Parsing/PeParser.h"
#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/Fixing/PeImageFixer.h"
#include "Application/Unpacking/UnpackEngine.h"
#include "Protocol/EngineHost/EngineHostProtocol.h"
#include "Tests/Support/EngineHostTestClient.h"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace
{
    using namespace upx_killer::engine;

    int failures{};

    void Expect(bool condition, std::string_view message)
    {
        if (!condition)
        {
            ++failures;
            std::cerr << "FAILED: " << message << '\n';
        }
    }

    std::vector<std::byte> MakePe64()
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
        section->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        bytes[0x200] = std::byte{ 0xC3 };
        return bytes;
    }

    class MemoryReader final : public dumping::IRemoteMemoryReader
    {
    public:
        explicit MemoryReader(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}

        dumping::MemoryRegion Query(LoadedAddress address) const override
        {
            return { address, static_cast<std::uint64_t>(bytes_.size()), true };
        }

        std::size_t Read(LoadedAddress address, std::span<std::byte> destination) const override
        {
            auto const offset = static_cast<std::size_t>(address.value - base_);
            if (offset >= bytes_.size()) return 0;
            auto const count = std::min(destination.size(), bytes_.size() - offset);
            std::copy_n(bytes_.begin() + offset, count, destination.begin());
            return count;
        }

        static constexpr std::uint64_t base_ = 0x180000000ull;

    private:
        std::vector<std::byte> bytes_;
    };

    void ParserAcceptsAmd64Executable()
    {
        auto bytes = MakePe64();
        auto const result = pe::PeParser::Parse(bytes);
        Expect(result.Succeeded(), "PE32+ AMD64 executable parses");
        Expect(result.layout && result.layout->entryPoint.value == 0x1000, "entry point RVA is preserved");
        Expect(result.layout && result.layout->sections.size() == 1, "section table is parsed");
    }

    void ParserRejectsTruncatedAndPe32Images()
    {
        auto truncated = MakePe64();
        truncated.resize(100);
        Expect(pe::PeParser::Parse(truncated).error == pe::PeError::Truncated, "truncated image is rejected");

        auto pe32 = MakePe64();
        reinterpret_cast<IMAGE_NT_HEADERS64*>(pe32.data() + 0x80)->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        Expect(pe::PeParser::Parse(pe32).error == pe::PeError::UnsupportedPe32, "PE32 is explicitly unsupported");
    }

    void DumperReadsVirtualImage()
    {
        auto file = MakePe64();
        auto parsed = pe::PeParser::Parse(file);
        std::vector<std::byte> memory(0x2000);
        std::copy_n(file.begin(), 0x200, memory.begin());
        memory[0x1000] = std::byte{ 0xC3 };
        MemoryReader reader(std::move(memory));
        auto result = dumping::ProcessImageDumper::Dump(
            reader,
            { LoadedAddress{ MemoryReader::base_ }, 0x2000 },
            *parsed.layout,
            { 0x4000 });
        Expect(result.Succeeded(), "virtual image dump succeeds");
        Expect(result.image && result.image->bytes[0x1000] == std::byte{ 0xC3 }, "virtual section bytes are captured");
    }

    void FixerCreatesExportablePartialImage()
    {
        auto file = MakePe64();
        auto parsed = pe::PeParser::Parse(file);
        dumping::DumpedImage dump{};
        dump.loadedBase = LoadedAddress{ MemoryReader::base_ };
        dump.bytes.resize(0x2000);
        std::copy_n(file.begin(), 0x200, dump.bytes.begin());
        dump.bytes[0x1000] = std::byte{ 0xC3 };

        auto fixed = pe::PeImageFixer::Rebuild(*parsed.layout, dump, { RelativeVirtualAddress{ 0x1000 }, std::nullopt });
        Expect(fixed.Succeeded(), "basic PE rebuild succeeds");
        Expect(fixed.image && fixed.image->quality == ArtifactQuality::Partial, "missing import plan is reported as partial");
        Expect(fixed.image && fixed.image->bytes.size() >= 0x400, "rebuilt file has raw section data");
    }

    void FixerRebuildsImportsFromAPlan()
    {
        auto file = MakePe64();
        auto parsed = pe::PeParser::Parse(file);
        dumping::DumpedImage dump{};
        dump.loadedBase = LoadedAddress{ MemoryReader::base_ };
        dump.bytes.resize(0x2000);
        std::copy_n(file.begin(), 0x200, dump.bytes.begin());

        ImportRebuildPlan plan{};
        ImportModulePlan module{};
        module.moduleName = "KERNEL32.dll";
        module.firstThunk = { 0x1000 };
        module.symbols.push_back({ std::string{ "ExitProcess" }, std::nullopt, 0 });
        plan.modules.push_back(std::move(module));
        auto fixed = pe::PeImageFixer::Rebuild(
            *parsed.layout, dump, { RelativeVirtualAddress{ 0x1000 }, std::move(plan) });
        Expect(fixed.Succeeded(), "a valid import plan is rebuilt");
        Expect(fixed.image && fixed.image->quality == ArtifactQuality::Complete, "rebuilt imports produce a complete artifact");
        if (fixed.image)
        {
            auto const reparsed = pe::PeParser::Parse(fixed.image->bytes);
            Expect(reparsed.layout && reparsed.layout->directories[IMAGE_DIRECTORY_ENTRY_IMPORT].address.value != 0,
                "rebuilt image advertises its import directory");
        }
    }

    void FixerPinsCapturedBaseWhenRelocationsAreIncomplete()
    {
        auto file = MakePe64();
        auto* sourceNt = reinterpret_cast<IMAGE_NT_HEADERS64*>(file.data() + 0x80);
        sourceNt->OptionalHeader.DllCharacteristics =
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
        sourceNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0x1000, 8 };
        auto parsed = pe::PeParser::Parse(file);
        dumping::DumpedImage dump{};
        dump.loadedBase = LoadedAddress{ 0x7ff700000000ull };
        dump.bytes.resize(0x2000);
        std::copy_n(file.begin(), 0x200, dump.bytes.begin());
        dump.bytes[0x1000] = std::byte{ 0xC3 };

        auto fixed = pe::PeImageFixer::Rebuild(*parsed.layout, dump, { RelativeVirtualAddress{ 0x1000 }, ImportRebuildPlan{} });
        Expect(fixed.Succeeded(), "fixer preserves a valid image while pinning the captured base");
        if (!fixed.image) return;
        auto const reparsed = pe::PeParser::Parse(fixed.image->bytes);
        Expect(reparsed.layout && reparsed.layout->preferredImageBase == dump.loadedBase.value,
            "rebuilt image uses the captured load base");
        if (!reparsed.layout) return;
        auto const* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(fixed.image->bytes.data() + reparsed.layout->ntHeaderOffset);
        Expect((nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0,
            "rebuilt image disables dynamic base relocation");
        Expect(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0 &&
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0,
            "rebuilt image clears the incomplete relocation directory");
    }

    void ProtocolRoundTripsAnExplicitRequest()
    {
        HANDLE readHandle{}, writeHandle{};
        SECURITY_ATTRIBUTES security{ sizeof(security), nullptr, FALSE };
        Expect(CreatePipe(&readHandle, &writeHandle, &security, 0) != FALSE, "protocol test pipe is created");
        if (!readHandle || !writeHandle) return;
        UnpackRequest sent{};
        sent.targetPath = L"C:\\Samples\\packed.exe";
        sent.outputPath = L"C:\\Temp\\packed.dumped.exe";
        sent.oep = RelativeVirtualAddress{ 0x1234 };
        sent.timeoutMilliseconds = 4321;
        sent.maximumImageSize = 0x12345678;
        Expect(protocol::WriteRequest(writeHandle, sent), "request frame is written");
        CloseHandle(writeHandle);
        UnpackRequest received{};
        Expect(protocol::ReadRequest(readHandle, received), "request frame is read");
        CloseHandle(readHandle);
        Expect(received.targetPath == sent.targetPath && received.outputPath == sent.outputPath,
            "protocol preserves paths");
        Expect(received.oep && received.oep->value == 0x1234 && received.timeoutMilliseconds == 4321,
            "protocol preserves execution limits");
    }

    void EngineCapturesFixtureAtItsEntryPoint()
    {
        wchar_t executablePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
        auto const directory = std::filesystem::path{ executablePath }.parent_path();
        auto const fixture = directory / L"upx-killer-engine-fixture.exe";
        auto const output = directory / L"fixture.dumped.exe";

        std::ifstream stream(fixture, std::ios::binary | std::ios::ate);
        Expect(static_cast<bool>(stream), "integration fixture exists");
        if (!stream) return;
        auto const size = static_cast<std::size_t>(stream.tellg());
        std::vector<std::byte> bytes(size);
        stream.seekg(0);
        stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        auto const parsed = pe::PeParser::Parse(bytes);
        Expect(parsed.Succeeded(), "integration fixture is a supported x64 PE");
        if (!parsed.layout) return;

        UnpackRequest request{};
        request.targetPath = fixture;
        request.outputPath = output;
        request.oep = parsed.layout->entryPoint;
        request.timeoutMilliseconds = 10'000;
        auto const result = application::UnpackEngine::Execute(request, {});
        Expect(result.outcome == EngineOutcome::Completed, "fixture capture produces a completed artifact");
        Expect(result.artifact && result.artifact->loaderMappable, "captured artifact passes non-executing image validation");
        std::error_code ignored;
        std::filesystem::remove(output, ignored);
    }

    void EngineHostRoundTripsARealCapture()
    {
        wchar_t executablePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, executablePath, MAX_PATH);
        auto const directory = std::filesystem::path{ executablePath }.parent_path();
        auto const repository = directory.parent_path().parent_path().parent_path();
        auto const host = repository / L"upx-killer" / L"x64" / L"Release" / L"upx-killer" / L"upx_killer_engine_host.exe";
        auto const fixture = directory / L"upx-killer-engine-fixture.exe";
        auto const output = directory / L"fixture.host.dumped.exe";

        std::ifstream stream(fixture, std::ios::binary | std::ios::ate);
        if (!stream) { Expect(false, "host fixture exists"); return; }
        std::vector<std::byte> bytes(static_cast<std::size_t>(stream.tellg()));
        stream.seekg(0);
        stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        auto parsed = pe::PeParser::Parse(bytes);
        if (!parsed.layout) { Expect(false, "host fixture parses"); return; }

        UnpackRequest request{};
        request.targetPath = fixture;
        request.outputPath = output;
        request.oep = parsed.layout->entryPoint;
        request.timeoutMilliseconds = 10'000;
        auto const execution = tests::ExecuteThroughEngineHost(host, request);
        Expect(execution.protocolSucceeded, "engine host protocol completes");
        Expect(execution.result.outcome == EngineOutcome::Completed && execution.result.artifact &&
            execution.result.artifact->loaderMappable,
            "engine host returns a validated completed artifact");
        std::error_code ignored;
        std::filesystem::remove(output, ignored);
    }
}

int RunOepDiscoveryTests();
int RunOepDiscoveryIntegrationTests();
int RunImportDiscoveryTests();
int AnalyzeAutomaticOepTarget(std::filesystem::path const& target);
int ValidateAutomaticOepTarget(std::filesystem::path const& target);
int ValidateAutomaticOepTargetThroughHost(std::filesystem::path const& target);

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring_view{ argv[1] } == L"--analyze-oep")
        return AnalyzeAutomaticOepTarget(argv[2]);
    if (argc == 3 && std::wstring_view{ argv[1] } == L"--validate-auto")
        return ValidateAutomaticOepTarget(argv[2]);
    if (argc == 3 && std::wstring_view{ argv[1] } == L"--validate-host")
        return ValidateAutomaticOepTargetThroughHost(argv[2]);
    ParserAcceptsAmd64Executable();
    ParserRejectsTruncatedAndPe32Images();
    DumperReadsVirtualImage();
    FixerCreatesExportablePartialImage();
    FixerRebuildsImportsFromAPlan();
    FixerPinsCapturedBaseWhenRelocationsAreIncomplete();
    ProtocolRoundTripsAnExplicitRequest();
    EngineCapturesFixtureAtItsEntryPoint();
    EngineHostRoundTripsARealCapture();
    failures += RunOepDiscoveryTests();
    failures += RunOepDiscoveryIntegrationTests();
    failures += RunImportDiscoveryTests();
    if (failures == 0)
    {
        std::cout << "All engine module tests passed.\n";
    }
    return failures == 0 ? 0 : 1;
}
