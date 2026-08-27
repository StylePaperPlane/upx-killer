#include "Application/Unpacking/UnpackEngine.h"

#include "Core/Dumping/ProcessImageDumper.h"
#include "Core/PE/Fixing/PeImageFixer.h"
#include "Core/PE/Imports/ImportDiscovery.h"
#include "Core/PE/Imports/ImportTableValidator.h"
#include "Core/PE/OepDiscovery/UpxOepLocator.h"
#include "Core/PE/Parsing/PeParser.h"
#include "Infrastructure/Windows/Debugging/WindowsDebugSession.h"

#include <Windows.h>

#include <fstream>
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

            if (progress) progress(EngineStage::Launching);
            std::optional<pe::FixedPeImage> repaired;
            auto const debugResult = debugging::WindowsDebugSession::Capture(
                { request.targetPath, std::move(oepTarget), parsed.layout->sizeOfImage,
                    std::chrono::milliseconds{ request.timeoutMilliseconds }, !request.imports.has_value() },
                [&](dumping::IRemoteMemoryReader const& reader,
                    dumping::LoadedImage const& loaded,
                    RelativeVirtualAddress resolvedOep,
                    pe::imports::RuntimeModuleSnapshot const& runtime)
                {
                    if (progress) progress(EngineStage::Dumping);
                    auto dump = dumping::ProcessImageDumper::Dump(reader, loaded, *parsed.layout, { request.maximumImageSize });
                    if (!dump.image) return dump.error;
                    std::optional<ImportRebuildPlan> imports = request.imports;
                    if (!imports)
                    {
                        if (progress) progress(EngineStage::RebuildingImports);
                        auto discovered = pe::imports::ImportDiscovery::Discover(dump.image->bytes, *parsed.layout, runtime);
                        if (!discovered.plan)
                        {
                            return discovered.error == pe::imports::ImportDiscoveryError::ImportsAmbiguous
                                ? EngineError::ImportsAmbiguous
                                : EngineError::ImportsNotFound;
                        }
                        imports = std::move(discovered.plan);
                    }
                    if (progress) progress(EngineStage::Fixing);
                    auto fixed = pe::PeImageFixer::Rebuild(*parsed.layout, *dump.image, { resolvedOep, std::move(imports) });
                    if (!fixed.image) return fixed.error;
                    auto fixedLayout = pe::PeParser::Parse(fixed.image->bytes);
                    if (!fixedLayout.layout || !pe::imports::ImportTableValidator::Validate(fixed.image->bytes, *fixedLayout.layout))
                        return EngineError::OutputValidationFailed;
                    fixed.image->warnings.insert(
                        fixed.image->warnings.end(), dump.image->warnings.begin(), dump.image->warnings.end());
                    repaired = std::move(*fixed.image);
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
            if (!repaired) return { EngineOutcome::Failed, EngineError::RebuildFailed };
            if (progress) progress(EngineStage::ValidatingOutput);
            if (!WriteAtomically(request.outputPath, repaired->bytes))
                return { EngineOutcome::Failed, EngineError::OutputWriteFailed };
            if (!ValidateImageWithoutExecuting(request.outputPath))
            {
                std::error_code ignored;
                std::filesystem::remove(request.outputPath, ignored);
                return { EngineOutcome::Failed, EngineError::OutputValidationFailed };
            }
            if (progress) progress(EngineStage::Completed);
            EngineArtifact artifact{ request.outputPath, repaired->quality, true, repaired->warnings };
            auto const outcome = repaired->quality == ArtifactQuality::Complete ? EngineOutcome::Completed : EngineOutcome::Partial;
            return { outcome, EngineError::None, std::move(artifact) };
        }
        catch (...)
        {
            return { EngineOutcome::Failed, EngineError::RebuildFailed };
        }
    }
}
