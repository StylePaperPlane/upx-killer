#include "pch.h"
#include "Infrastructure/EngineHost/EngineHostClient.h"

#include "Protocol/EngineHost/EngineHostProtocol.h"

#include <Windows.h>

#include <array>
#include <chrono>
#include <stdexcept>
#include <vector>

namespace
{
    void CleanupStaleArtifacts(std::filesystem::path const& root) noexcept
    {
        try
        {
            if (!std::filesystem::is_directory(root)) return;
            auto const cutoff = std::filesystem::file_time_type::clock::now() - std::chrono::hours{ 24 * 7 };
            for (auto const& entry : std::filesystem::directory_iterator(root))
            {
                std::error_code error;
                if (entry.is_directory(error) && !error && entry.last_write_time(error) < cutoff && !error)
                    std::filesystem::remove_all(entry.path(), error);
            }
        }
        catch (...) {}
    }

    class UniqueHandle final
    {
    public:
        UniqueHandle() = default;
        explicit UniqueHandle(HANDLE value) : value_(value) {}
        ~UniqueHandle() { reset(); }
        UniqueHandle(UniqueHandle const&) = delete;
        UniqueHandle& operator=(UniqueHandle const&) = delete;
        [[nodiscard]] HANDLE get() const noexcept { return value_; }
        [[nodiscard]] HANDLE release() noexcept { auto value = value_; value_ = nullptr; return value; }
        void reset(HANDLE value = nullptr) noexcept
        {
            if (value_ && value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
            value_ = value;
        }
        explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }
    private:
        HANDLE value_{};
    };

    class AttributeList final
    {
    public:
        AttributeList()
        {
            SIZE_T size{};
            InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
            storage_.resize(size);
            list_ = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage_.data());
            if (!InitializeProcThreadAttributeList(list_, 1, 0, &size)) throw std::runtime_error("attribute list");
        }
        ~AttributeList() { if (list_) DeleteProcThreadAttributeList(list_); }
        [[nodiscard]] LPPROC_THREAD_ATTRIBUTE_LIST get() const noexcept { return list_; }
    private:
        std::vector<std::byte> storage_;
        LPPROC_THREAD_ATTRIBUTE_LIST list_{};
    };
}

namespace upx_killer::infrastructure
{
    EngineHostClient::EngineHostClient(
        std::filesystem::path hostPath,
        std::shared_ptr<application::ITemporaryFileSettingsStore> settingsStore)
        : m_hostPath(std::move(hostPath)),
          m_settingsStore(std::move(settingsStore))
    {
    }

    std::filesystem::path EngineHostClient::AdjacentHostPath()
    {
        std::vector<wchar_t> buffer(32768);
        auto const length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0 || length == buffer.size()) return {};
        return std::filesystem::path{ std::wstring_view{ buffer.data(), length } }.parent_path() /
            L"upx_killer_engine_host.exe";
    }

    engine::EngineResult EngineHostClient::Execute(
        engine::UnpackRequest const& request,
        ProgressCallback const& progress) noexcept
    {
        try
        {
            if (!std::filesystem::is_regular_file(m_hostPath))
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, ERROR_FILE_NOT_FOUND };
            if (!m_settingsStore)
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed };

            auto const temporaryFileSettings = m_settingsStore->Load();
            auto const& artifactRoot = temporaryFileSettings.directory;
            if (artifactRoot.empty())
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed };
            if (temporaryFileSettings.deleteAfterExport)
                CleanupStaleArtifacts(artifactRoot);

            auto hostRequest = request;
            if (hostRequest.outputPath.empty())
            {
                auto const session = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
                hostRequest.outputPath = artifactRoot / session /
                    (request.targetPath.stem().wstring() + L".dumped.exe");
            }

            SECURITY_ATTRIBUTES security{ sizeof(security), nullptr, TRUE };
            HANDLE requestReadRaw{}, requestWriteRaw{};
            if (!CreatePipe(&requestReadRaw, &requestWriteRaw, &security, 0))
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, GetLastError() };
            UniqueHandle requestRead{ requestReadRaw }, requestWrite{ requestWriteRaw };
            HANDLE resultReadRaw{}, resultWriteRaw{};
            if (!CreatePipe(&resultReadRaw, &resultWriteRaw, &security, 0))
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, GetLastError() };
            UniqueHandle resultRead{ resultReadRaw }, resultWrite{ resultWriteRaw };
            if (!SetHandleInformation(requestWrite.get(), HANDLE_FLAG_INHERIT, 0) ||
                !SetHandleInformation(resultRead.get(), HANDLE_FLAG_INHERIT, 0))
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, GetLastError() };

            UniqueHandle nullOutput{ CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &security, OPEN_EXISTING, 0, nullptr) };
            if (!nullOutput) return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, GetLastError() };
            std::array<HANDLE, 3> inherited{ requestRead.get(), resultWrite.get(), nullOutput.get() };
            AttributeList attributes;
            if (!UpdateProcThreadAttribute(
                    attributes.get(), 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    inherited.data(), sizeof(inherited), nullptr, nullptr))
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, GetLastError() };

            STARTUPINFOEXW startup{};
            startup.StartupInfo.cb = sizeof(startup);
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = requestRead.get();
            startup.StartupInfo.hStdOutput = resultWrite.get();
            startup.StartupInfo.hStdError = nullOutput.get();
            startup.lpAttributeList = attributes.get();
            PROCESS_INFORMATION processInformation{};
            auto commandLine = L"\"" + m_hostPath.wstring() + L"\"";
            if (!CreateProcessW(
                    m_hostPath.c_str(), commandLine.data(), nullptr, nullptr, TRUE,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    nullptr, m_hostPath.parent_path().c_str(), &startup.StartupInfo, &processInformation))
                return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed, std::nullopt, GetLastError() };

            UniqueHandle process{ processInformation.hProcess };
            UniqueHandle thread{ processInformation.hThread };
            requestRead.reset();
            resultWrite.reset();
            nullOutput.reset();

            if (!engine::protocol::WriteRequest(requestWrite.get(), hostRequest))
            {
                TerminateProcess(process.get(), ERROR_WRITE_FAULT);
                return { engine::EngineOutcome::Failed, engine::EngineError::ProtocolMismatch, std::nullopt, GetLastError() };
            }
            requestWrite.reset();
            engine::EngineResult result{};
            for (;;)
            {
                engine::protocol::HostResponse response{};
                if (!engine::protocol::ReadResponse(resultRead.get(), response))
                {
                    TerminateProcess(process.get(), ERROR_READ_FAULT);
                    return { engine::EngineOutcome::Failed, engine::EngineError::ProtocolMismatch, std::nullopt, GetLastError() };
                }
                if (response.progress && progress) progress(*response.progress);
                if (response.result)
                {
                    result = std::move(*response.result);
                    break;
                }
            }
            if (WaitForSingleObject(process.get(), 5'000) == WAIT_TIMEOUT)
                TerminateProcess(process.get(), WAIT_TIMEOUT);
            return result;
        }
        catch (...)
        {
            return { engine::EngineOutcome::Failed, engine::EngineError::LaunchFailed };
        }
    }
}
