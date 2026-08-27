#include "Infrastructure/Windows/Debugging/DebugProcess.h"

#include <utility>

namespace upx_killer::engine::debugging
{
    DebugProcess::~DebugProcess()
    {
        Reset();
    }

    DebugProcess::DebugProcess(DebugProcess&& other) noexcept
        : process_(std::exchange(other.process_, nullptr)),
          primaryThread_(std::exchange(other.primaryThread_, nullptr)),
          job_(std::exchange(other.job_, nullptr)),
          processId_(std::exchange(other.processId_, 0))
    {
    }

    DebugProcess& DebugProcess::operator=(DebugProcess&& other) noexcept
    {
        if (this != &other)
        {
            Reset();
            process_ = std::exchange(other.process_, nullptr);
            primaryThread_ = std::exchange(other.primaryThread_, nullptr);
            job_ = std::exchange(other.job_, nullptr);
            processId_ = std::exchange(other.processId_, 0);
        }
        return *this;
    }

    std::optional<DebugProcess> DebugProcess::Launch(
        std::filesystem::path const& targetPath,
        std::uint32_t& nativeError) noexcept
    {
        nativeError = ERROR_SUCCESS;
        STARTUPINFOW startup{ sizeof(startup) };
        PROCESS_INFORMATION information{};
        auto commandLine = L"\"" + targetPath.wstring() + L"\"";
        if (!CreateProcessW(
                targetPath.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                nullptr, targetPath.parent_path().c_str(), &startup, &information))
        {
            nativeError = GetLastError();
            return std::nullopt;
        }

        DebugProcess result;
        result.process_ = information.hProcess;
        result.primaryThread_ = information.hThread;
        result.processId_ = information.dwProcessId;
        result.job_ = CreateJobObjectW(nullptr, nullptr);
        if (!result.job_)
        {
            nativeError = GetLastError();
            TerminateProcess(result.process_, nativeError);
            return std::nullopt;
        }

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(
                result.job_, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(result.job_, result.process_))
        {
            nativeError = GetLastError();
            TerminateProcess(result.process_, nativeError);
            return std::nullopt;
        }
        if (ResumeThread(result.primaryThread_) == static_cast<DWORD>(-1))
        {
            nativeError = GetLastError();
            result.Terminate(nativeError);
            return std::nullopt;
        }
        return result;
    }

    void DebugProcess::Terminate(std::uint32_t exitCode) noexcept
    {
        if (job_) TerminateJobObject(job_, exitCode);
        else if (process_) TerminateProcess(process_, exitCode);
    }

    void DebugProcess::Reset() noexcept
    {
        if (job_) CloseHandle(job_);
        if (primaryThread_) CloseHandle(primaryThread_);
        if (process_) CloseHandle(process_);
        job_ = nullptr;
        primaryThread_ = nullptr;
        process_ = nullptr;
        processId_ = 0;
    }
}
