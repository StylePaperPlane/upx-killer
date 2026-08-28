#include "Application/Unpacking/UnpackEngine.h"

#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/Imports/ImportDiscovery.h"
#include "Core/PE/Imports/ImportTableValidator.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Core/PE/Rebasing/NoSourceRelocations/NoSourceRelocationsImagePreparer.h"
#include "Core/PE/Rebasing/PeFileRebaser.h"
#include "Core/PE/Relocations/RelocationReconstructor.h"
#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"
#include "Infrastructure/Windows/Verification/ExecutableVerifier.h"

#include <Windows.h>

#include <fstream>
#include <array>
#include <limits>
#include <vector>

namespace
{
    using namespace upx_killer::engine;

    EngineError MapParseError(pe::PeError error)
    {
        switch (error)
        {
        case pe::PeError::UnsupportedPe32: return EngineError::UnsupportedPe32;
        case pe::PeError::UnsupportedArchitecture: return EngineError::UnsupportedArchitecture;
        case pe::PeError::UnsupportedImageKind: return EngineError::UnsupportedImageKind;
        default: return EngineError::InvalidPe;
        }
    }

    bool WriteAtomically(std::filesystem::path const& path, std::span<std::byte const> bytes)
    {
        if (path.empty()) return false;
        std::error_code error;
        std::filesystem::create_directories(path.parent_path(), error);
        if (error) return false;
        auto temporary = path;
        temporary += L".tmp";
        {
            std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
            if (!stream) return false;
            stream.write(reinterpret_cast<char const*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            if (!stream) return false;
        }
        if (!MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            std::filesystem::remove(temporary, error);
            return false;
        }
        return true;
    }

    bool ValidateImageWithoutExecuting(std::filesystem::path const& path)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
        if (!mapping) { CloseHandle(file); return false; }
        void* view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        if (view) UnmapViewOfFile(view);
        CloseHandle(mapping);
        CloseHandle(file);
        return view != nullptr;
    }


}

namespace upx_killer::engine::application
{
    EngineResult UnpackEngine::Execute(
        UnpackRequest const& request,
        ProgressCallback const& progress,
        std::stop_token stopToken) noexcept
    {
        try
        {
            if (progress) progress(EngineStage::Validating);
            std::ifstream input(request.targetPath, std::ios::binary | std::ios::ate);
            if (!input) return { EngineOutcome::Failed, EngineError::InvalidPe };
            auto const end = input.tellg();
            if (end <= 0 || static_cast<std::uint64_t>(end) > request.maximumImageSize)
                return { EngineOutcome::Failed, EngineError::InvalidPe };
            std::vector<std::byte> source(static_cast<std::size_t>(end));
            input.seekg(0);
            input.read(reinterpret_cast<char*>(source.data()), static_cast<std::streamsize>(source.size()));
            if (!input) return { EngineOutcome::Failed, EngineError::InvalidPe };

            auto parsed = pe::PeParser::Parse(source);
            if (!parsed.layout)
            {
                auto const error = MapParseError(parsed.error);
                auto const outcome = error == EngineError::UnsupportedPe32 || error == EngineError::UnsupportedArchitecture ||
                    error == EngineError::UnsupportedImageKind ? EngineOutcome::UnsupportedTarget : EngineOutcome::Failed;
                return { outcome, error };
            }
            if (request.oep && request.oep->value >= parsed.layout->sizeOfImage)
                return { EngineOutcome::Failed, EngineError::OepOutOfRange };

            std::variant<RelativeVirtualAddress, pe::oep::OepDiscoveryPlan> oepTarget;
            if (request.oep)
            {
                oepTarget = *request.oep;
            }
            else
            {
                if (progress) progress(EngineStage::DiscoveringOep);
                auto discovery = pe::oep::UpxOepLocator::Analyze(source, *parsed.layout);
                if (!discovery.plan)
                {
                    if (discovery.error == pe::oep::OepDiscoveryError::UnsupportedPacker)
                        return { EngineOutcome::UnsupportedTarget, EngineError::UnsupportedPacker };
                    return { EngineOutcome::OepNotFound, EngineError::OepNotFound };
                }
                oepTarget = std::move(*discovery.plan);
            }

            constexpr std::array<std::uint64_t, 3> ControlledBases{
                0x140000000ull,
                0x180000000ull,
                0x1c0000000ull,
            };
            struct StagedImage
            {
                std::vector<std::byte> bytes;
                LoadedAddress requiredBase;
                std::vector<pe::rebasing::SourceRelocationSlot> sourceSlots;
            };

            auto const& sourceRelocationDirectory =
                parsed.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            auto const noSourceRelocations =
                sourceRelocationDirectory.address.value == 0 &&
                sourceRelocationDirectory.size == 0;
            auto const automaticUpx =
                std::holds_alternative<pe::oep::OepDiscoveryPlan>(oepTarget);
            if (noSourceRelocations && !automaticUpx)
                return { EngineOutcome::Failed, EngineError::SourceRelocationsInvalid };

            std::vector<StagedImage> stagedImages;
            stagedImages.reserve(ControlledBases.size());
            for (auto const base : ControlledBases)
            {
                if (noSourceRelocations)
                {
                    auto prepared =
                        pe::rebasing::NoSourceRelocationsImagePreparer::Prepare(
                            source, *parsed.layout, LoadedAddress{ base });
                    if (!prepared.image)
                    {
                        return {
                            EngineOutcome::Failed,
                            EngineError::SourceRelocationsInvalid
                        };
                    }
                    stagedImages.push_back({
                        std::move(prepared.image->bytes),
                        prepared.image->requiredBase,
                        {},
                    });
                }
                else
                {
                    auto rebased = pe::rebasing::PeFileRebaser::Rebase(
                        source, *parsed.layout, LoadedAddress{ base });
                    if (!rebased.image)
                    {
                        return {
                            EngineOutcome::Failed,
                            EngineError::SourceRelocationsInvalid
                        };
                    }
                    stagedImages.push_back({
                        std::move(rebased.image->bytes),
                        rebased.image->requiredBase,
                        std::move(rebased.image->sourceSlots),
                    });
                }
            }

            struct CapturedRun
            {
                dumping::DumpedImage image;
                RelativeVirtualAddress oep;
                pe::imports::RuntimeModuleSnapshot runtime;
            };
            std::vector<CapturedRun> captures;
            captures.reserve(ControlledBases.size());
            if (progress) progress(EngineStage::CapturingRelocations);
            for (std::size_t index = 0; index < stagedImages.size(); ++index)
            {
                if (progress) progress(EngineStage::Launching);
                std::optional<CapturedRun> captured;
                auto const debugResult = debugging::WindowsDebugSession::Capture(
                    { request.targetPath, oepTarget, parsed.layout->sizeOfImage,
                        std::chrono::milliseconds{ request.timeoutMilliseconds },
                        index == 0 && !request.imports.has_value(),
                        stagedImages[index].bytes,
                        stagedImages[index].requiredBase },
                    [&](dumping::IRemoteMemoryReader const& reader,
                        dumping::LoadedImage const& loaded,
                        RelativeVirtualAddress resolvedOep,
                        pe::imports::RuntimeModuleSnapshot const& runtime)
                    {
                        if (progress) progress(EngineStage::Dumping);
                        auto dump = dumping::ProcessImageDumper::Dump(
                            reader, loaded, *parsed.layout, { request.maximumImageSize });
                        if (!dump.image) return dump.error;
                        captured = CapturedRun{
                            std::move(*dump.image),
                            resolvedOep,
                            runtime,
                        };
                        return EngineError::None;
                    },
                    stopToken);
                if (!debugResult.Succeeded())
                {
                    auto outcome = EngineOutcome::Failed;
                    if (debugResult.error == EngineError::TimedOut) outcome = EngineOutcome::TimedOut;
                    else if (debugResult.error == EngineError::Cancelled) outcome = EngineOutcome::Cancelled;
                    else if (debugResult.error == EngineError::OepNotFound) outcome = EngineOutcome::OepNotFound;
                    return { outcome, debugResult.error, std::nullopt, debugResult.nativeError };
                }
                if (!captured)
                    return { EngineOutcome::Failed, EngineError::DumpIncomplete };
                if (!captures.empty() && captured->oep.value != captures.front().oep.value)
                    return { EngineOutcome::Failed, EngineError::RelocationEvidenceInsufficient };
                captures.push_back(std::move(*captured));
            }

            std::optional<ImportRebuildPlan> imports = request.imports;
            if (!imports)
            {
                if (progress) progress(EngineStage::RebuildingImports);
                auto discovered = pe::imports::ImportDiscovery::Discover(
                    captures.front().image.bytes, *parsed.layout, captures.front().runtime);
                if (!discovered.plan)
                {
                    return {
                        EngineOutcome::Failed,
                        discovered.error == pe::imports::ImportDiscoveryError::ImportsAmbiguous
                            ? EngineError::ImportsAmbiguous
                            : EngineError::ImportsNotFound
                    };
                }
                imports = std::move(discovered.plan);
            }

            if (progress) progress(EngineStage::RebuildingRelocations);
            std::array<pe::relocations::LoadedImageSnapshot, 3> snapshots{
                pe::relocations::LoadedImageSnapshot{
                    captures[0].image.loadedBase, captures[0].image.bytes },
                pe::relocations::LoadedImageSnapshot{
                    captures[1].image.loadedBase, captures[1].image.bytes },
                pe::relocations::LoadedImageSnapshot{
                    captures[2].image.loadedBase, captures[2].image.bytes },
            };
            auto relocations = pe::relocations::RelocationReconstructor::Reconstruct(
                snapshots,
                request.oep
                    ? std::span<pe::rebasing::SourceRelocationSlot const>{}
                    : std::span<pe::rebasing::SourceRelocationSlot const>{
                        stagedImages.front().sourceSlots },
                parsed.layout->sizeOfHeaders,
                parsed.layout->sizeOfImage,
                LoadedAddress{ ControlledBases.front() });
            if (!relocations.plan)
            {
                auto error = EngineError::RelocationEvidenceInsufficient;
                if (relocations.error == pe::relocations::RelocationRebuildError::CandidatesAmbiguous)
                    error = EngineError::RelocationCandidatesAmbiguous;
                return { EngineOutcome::Failed, error };
            }
            auto const expectedRelocationCount = relocations.plan->slots.size();

            if (progress) progress(EngineStage::Fixing);
            auto fixed = pe::PeImageFixer::Rebuild(
                *parsed.layout,
                captures.front().image,
                { captures.front().oep, std::move(imports), std::move(*relocations.plan) });
            if (!fixed.image)
                return { EngineOutcome::Failed, fixed.error };
            auto fixedLayout = pe::PeParser::Parse(fixed.image->bytes);
            if (!fixedLayout.layout)
                return { EngineOutcome::Failed, EngineError::OutputValidationFailed };
            if (!pe::imports::ImportTableValidator::Validate(
                fixed.image->bytes, *fixedLayout.layout))
                return { EngineOutcome::Failed, EngineError::OutputValidationFailed };
            if (fixedLayout.layout->preferredImageBase != ControlledBases.front() ||
                fixedLayout.layout->directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].address.value == 0)
                return { EngineOutcome::Failed, EngineError::RelocationValidationFailed };
            auto relocationProbe = pe::rebasing::PeFileRebaser::Rebase(
                fixed.image->bytes,
                *fixedLayout.layout,
                LoadedAddress{ 0x200000000ull });
            if (!relocationProbe.image ||
                relocationProbe.image->sourceSlots.size() !=
                    expectedRelocationCount)
                return { EngineOutcome::Failed, EngineError::RelocationValidationFailed };
            fixed.image->warnings.insert(
                fixed.image->warnings.end(),
                captures.front().image.warnings.begin(),
                captures.front().image.warnings.end());
            auto repaired = std::move(*fixed.image);
            if (progress) progress(EngineStage::ValidatingOutput);
            if (!WriteAtomically(request.outputPath, repaired.bytes))
                return { EngineOutcome::Failed, EngineError::OutputWriteFailed };
            if (!ValidateImageWithoutExecuting(request.outputPath))
            {
                std::error_code ignored;
                std::filesystem::remove(request.outputPath, ignored);
                return { EngineOutcome::Failed, EngineError::OutputValidationFailed };
            }
            auto const launchVerification = verification::ExecutableVerifier::Verify(
                request.outputPath,
                request.outputPath.parent_path(),
                3000);
            if (!launchVerification.completed && !launchVerification.timedOut)
            {
                std::error_code ignored;
                std::filesystem::remove(request.outputPath, ignored);
                return { EngineOutcome::Failed, EngineError::OutputValidationFailed,
                    std::nullopt, launchVerification.nativeError };
            }
            if (launchVerification.completed && launchVerification.exitCode != 0)
            {
                std::error_code ignored;
                std::filesystem::remove(request.outputPath, ignored);
                return { EngineOutcome::Failed, EngineError::OutputValidationFailed,
                    std::nullopt, launchVerification.exitCode };
            }
            if (progress) progress(EngineStage::Completed);
            EngineArtifact artifact{ request.outputPath, repaired.quality, true, repaired.warnings };
            auto const outcome = repaired.quality == ArtifactQuality::Complete ? EngineOutcome::Completed : EngineOutcome::Partial;
            return { outcome, EngineError::None, std::move(artifact) };
        }
        catch (...)
        {
            return { EngineOutcome::Failed, EngineError::RebuildFailed };
        }
    }
}
