#include "Protocol/EngineHost/EngineHostProtocol.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <span>
#include <vector>

namespace
{
    constexpr std::uint32_t Magic = 0x4b585055;
    constexpr std::uint32_t RequestType = 1;
    constexpr std::uint32_t ResultType = 2;
    constexpr std::uint32_t ProgressType = 3;

    bool WriteExact(HANDLE handle, std::span<std::byte const> bytes)
    {
        std::size_t offset{};
        while (offset < bytes.size())
        {
            DWORD written{};
            auto const chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, std::numeric_limits<DWORD>::max()));
            if (!WriteFile(handle, bytes.data() + offset, chunk, &written, nullptr) || written == 0) return false;
            offset += written;
        }
        return true;
    }

    bool ReadExact(HANDLE handle, std::span<std::byte> bytes)
    {
        std::size_t offset{};
        while (offset < bytes.size())
        {
            DWORD read{};
            auto const chunk = static_cast<DWORD>(std::min<std::size_t>(bytes.size() - offset, std::numeric_limits<DWORD>::max()));
            if (!ReadFile(handle, bytes.data() + offset, chunk, &read, nullptr) || read == 0) return false;
            offset += read;
        }
        return true;
    }

    void PutU32(std::vector<std::byte>& bytes, std::uint32_t value)
    {
        for (unsigned shift = 0; shift < 32; shift += 8) bytes.push_back(static_cast<std::byte>((value >> shift) & 0xff));
    }

    void PutU64(std::vector<std::byte>& bytes, std::uint64_t value)
    {
        for (unsigned shift = 0; shift < 64; shift += 8) bytes.push_back(static_cast<std::byte>((value >> shift) & 0xff));
    }

    bool GetU32(std::span<std::byte const> bytes, std::size_t& offset, std::uint32_t& value)
    {
        if (offset > bytes.size() || 4 > bytes.size() - offset) return false;
        value = 0;
        for (unsigned shift = 0; shift < 32; shift += 8) value |= std::to_integer<std::uint32_t>(bytes[offset++]) << shift;
        return true;
    }

    bool GetU64(std::span<std::byte const> bytes, std::size_t& offset, std::uint64_t& value)
    {
        if (offset > bytes.size() || 8 > bytes.size() - offset) return false;
        value = 0;
        for (unsigned shift = 0; shift < 64; shift += 8) value |= std::to_integer<std::uint64_t>(bytes[offset++]) << shift;
        return true;
    }

    void PutWide(std::vector<std::byte>& bytes, std::wstring const& value)
    {
        PutU32(bytes, static_cast<std::uint32_t>(value.size()));
        auto const* first = reinterpret_cast<std::byte const*>(value.data());
        bytes.insert(bytes.end(), first, first + value.size() * sizeof(wchar_t));
    }

    bool GetWide(std::span<std::byte const> bytes, std::size_t& offset, std::wstring& value)
    {
        std::uint32_t count{};
        if (!GetU32(bytes, offset, count)) return false;
        auto const byteCount = static_cast<std::uint64_t>(count) * sizeof(wchar_t);
        if (byteCount > bytes.size() - offset) return false;
        value.resize(count);
        std::memcpy(value.data(), bytes.data() + offset, static_cast<std::size_t>(byteCount));
        offset += static_cast<std::size_t>(byteCount);
        return true;
    }

    void PutNarrow(std::vector<std::byte>& bytes, std::string const& value)
    {
        PutU32(bytes, static_cast<std::uint32_t>(value.size()));
        auto const* first = reinterpret_cast<std::byte const*>(value.data());
        bytes.insert(bytes.end(), first, first + value.size());
    }

    bool GetNarrow(std::span<std::byte const> bytes, std::size_t& offset, std::string& value)
    {
        std::uint32_t count{};
        if (!GetU32(bytes, offset, count) || count > bytes.size() - offset) return false;
        value.assign(reinterpret_cast<char const*>(bytes.data() + offset), count);
        offset += count;
        return true;
    }

    bool WriteFrame(HANDLE pipe, std::uint32_t type, std::vector<std::byte> const& payload)
    {
        if (payload.size() > upx_killer::engine::protocol::MaximumFrameSize) return false;
        std::vector<std::byte> header;
        PutU32(header, Magic);
        PutU32(header, upx_killer::engine::protocol::ProtocolVersion);
        PutU32(header, type);
        PutU32(header, static_cast<std::uint32_t>(payload.size()));
        return WriteExact(pipe, header) && WriteExact(pipe, payload);
    }

    bool ReadFrameAny(HANDLE pipe, std::uint32_t& messageType, std::vector<std::byte>& payload)
    {
        std::array<std::byte, 16> header{};
        if (!ReadExact(pipe, header)) return false;
        std::size_t offset{};
        std::uint32_t magic{}, version{}, type{}, size{};
        if (!GetU32(header, offset, magic) || !GetU32(header, offset, version) ||
            !GetU32(header, offset, type) || !GetU32(header, offset, size)) return false;
        if (magic != Magic || version != upx_killer::engine::protocol::ProtocolVersion ||
            size > upx_killer::engine::protocol::MaximumFrameSize) return false;
        messageType = type;
        payload.resize(size);
        return ReadExact(pipe, payload);
    }

    bool ReadFrame(HANDLE pipe, std::uint32_t expectedType, std::vector<std::byte>& payload)
    {
        std::uint32_t type{};
        return ReadFrameAny(pipe, type, payload) && type == expectedType;
    }

    bool DecodeResult(std::span<std::byte const> payload, upx_killer::engine::EngineResult& result)
    {
        using namespace upx_killer::engine;
        std::size_t offset{};
        std::uint32_t outcome{}, error{}, native{}, hasArtifact{};
        if (!GetU32(payload, offset, outcome) || !GetU32(payload, offset, error) ||
            !GetU32(payload, offset, native) || !GetU32(payload, offset, hasArtifact)) return false;
        result = {};
        result.outcome = static_cast<EngineOutcome>(outcome);
        result.error = static_cast<EngineError>(error);
        result.nativeError = native;
        if (hasArtifact)
        {
            EngineArtifact artifact{};
            std::wstring path;
            std::uint32_t quality{}, mappable{}, warningCount{};
            if (!GetWide(payload, offset, path) || !GetU32(payload, offset, quality) ||
                !GetU32(payload, offset, mappable) || !GetU32(payload, offset, warningCount) ||
                warningCount > 4096) return false;
            artifact.path = path;
            artifact.quality = static_cast<ArtifactQuality>(quality);
            artifact.loaderMappable = mappable != 0;
            for (std::uint32_t i = 0; i < warningCount; ++i)
            {
                std::string warning;
                if (!GetNarrow(payload, offset, warning)) return false;
                artifact.warnings.push_back(std::move(warning));
            }
            result.artifact = std::move(artifact);
        }
        return offset == payload.size();
    }
}

namespace upx_killer::engine::protocol
{
    bool WriteRequest(HANDLE pipe, UnpackRequest const& request) noexcept
    {
        try
        {
            std::vector<std::byte> payload;
            PutWide(payload, request.targetPath.wstring());
            PutWide(payload, request.outputPath.wstring());
            PutU32(payload, request.oep ? 1u : 0u);
            PutU32(payload, request.oep ? request.oep->value : 0u);
            PutU32(payload, request.timeoutMilliseconds);
            PutU64(payload, request.maximumImageSize);
            PutU32(payload, request.imports ? 1u : 0u);
            PutU32(payload, request.imports ? static_cast<std::uint32_t>(request.imports->modules.size()) : 0u);
            if (request.imports)
            {
                for (auto const& module : request.imports->modules)
                {
                    PutNarrow(payload, module.moduleName);
                    PutU32(payload, module.firstThunk.value);
                    PutU32(payload, static_cast<std::uint32_t>(module.symbols.size()));
                    for (auto const& symbol : module.symbols)
                    {
                        PutU32(payload, symbol.ordinal ? 1u : 0u);
                        PutU32(payload, symbol.ordinal.value_or(0));
                        PutU32(payload, symbol.hint);
                        PutNarrow(payload, symbol.name.value_or(std::string{}));
                    }
                }
            }
            return WriteFrame(pipe, RequestType, payload);
        }
        catch (...) { return false; }
    }

    bool ReadRequest(HANDLE pipe, UnpackRequest& request) noexcept
    {
        try
        {
            std::vector<std::byte> payload;
            if (!ReadFrame(pipe, RequestType, payload)) return false;
            std::size_t offset{};
            std::wstring target, output;
            std::uint32_t hasOep{}, oep{}, timeout{}, hasImports{}, moduleCount{};
            std::uint64_t maximum{};
            if (!GetWide(payload, offset, target) || !GetWide(payload, offset, output) ||
                !GetU32(payload, offset, hasOep) || !GetU32(payload, offset, oep) ||
                !GetU32(payload, offset, timeout) || !GetU64(payload, offset, maximum) || !GetU32(payload, offset, hasImports) ||
                !GetU32(payload, offset, moduleCount) || moduleCount > 4096) return false;
            request = {};
            request.targetPath = target;
            request.outputPath = output;
            if (hasOep) request.oep = RelativeVirtualAddress{ oep };
            request.timeoutMilliseconds = timeout;
            request.maximumImageSize = maximum;
            if (hasImports > 1 || (hasImports == 0 && moduleCount != 0)) return false;
            if (hasImports) request.imports.emplace();
            for (std::uint32_t moduleIndex = 0; moduleIndex < moduleCount; ++moduleIndex)
            {
                ImportModulePlan module{};
                std::uint32_t symbolCount{};
                if (!GetNarrow(payload, offset, module.moduleName) || !GetU32(payload, offset, module.firstThunk.value) ||
                    !GetU32(payload, offset, symbolCount) || symbolCount > 65536) return false;
                for (std::uint32_t symbolIndex = 0; symbolIndex < symbolCount; ++symbolIndex)
                {
                    ImportSymbol symbol{};
                    std::uint32_t byOrdinal{}, ordinal{}, hint{};
                    std::string name;
                    if (!GetU32(payload, offset, byOrdinal) || !GetU32(payload, offset, ordinal) ||
                        !GetU32(payload, offset, hint) || !GetNarrow(payload, offset, name)) return false;
                    symbol.hint = static_cast<std::uint16_t>(hint);
                    if (byOrdinal) symbol.ordinal = static_cast<std::uint16_t>(ordinal);
                    else symbol.name = std::move(name);
                    module.symbols.push_back(std::move(symbol));
                }
                request.imports->modules.push_back(std::move(module));
            }
            return offset == payload.size();
        }
        catch (...) { return false; }
    }

    bool WriteProgress(HANDLE pipe, EngineStage stage) noexcept
    {
        try
        {
            std::vector<std::byte> payload;
            PutU32(payload, static_cast<std::uint32_t>(stage));
            return WriteFrame(pipe, ProgressType, payload);
        }
        catch (...) { return false; }
    }

    bool WriteResult(HANDLE pipe, EngineResult const& result) noexcept
    {
        try
        {
            std::vector<std::byte> payload;
            PutU32(payload, static_cast<std::uint32_t>(result.outcome));
            PutU32(payload, static_cast<std::uint32_t>(result.error));
            PutU32(payload, result.nativeError);
            PutU32(payload, result.artifact ? 1u : 0u);
            if (result.artifact)
            {
                PutWide(payload, result.artifact->path.wstring());
                PutU32(payload, static_cast<std::uint32_t>(result.artifact->quality));
                PutU32(payload, result.artifact->loaderMappable ? 1u : 0u);
                PutU32(payload, static_cast<std::uint32_t>(result.artifact->warnings.size()));
                for (auto const& warning : result.artifact->warnings) PutNarrow(payload, warning);
            }
            return WriteFrame(pipe, ResultType, payload);
        }
        catch (...) { return false; }
    }

    bool ReadResult(HANDLE pipe, EngineResult& result) noexcept
    {
        try
        {
            std::vector<std::byte> payload;
            if (!ReadFrame(pipe, ResultType, payload)) return false;
            return DecodeResult(payload, result);
        }
        catch (...) { return false; }
    }

    bool ReadResponse(HANDLE pipe, HostResponse& response) noexcept
    {
        try
        {
            response = {};
            std::vector<std::byte> payload;
            std::uint32_t type{};
            if (!ReadFrameAny(pipe, type, payload)) return false;
            if (type == ProgressType)
            {
                std::size_t offset{};
                std::uint32_t stage{};
                if (!GetU32(payload, offset, stage) || offset != payload.size() ||
                    stage > static_cast<std::uint32_t>(EngineStage::Completed))
                    return false;
                response.progress = static_cast<EngineStage>(stage);
                return true;
            }
            if (type == ResultType)
            {
                EngineResult result{};
                if (!DecodeResult(payload, result)) return false;
                response.result = std::move(result);
                return true;
            }
            return false;
        }
        catch (...) { return false; }
    }
}
