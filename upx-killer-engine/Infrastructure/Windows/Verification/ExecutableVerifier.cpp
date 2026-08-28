#include "Infrastructure/Windows/Verification/ExecutableVerifier.h"

#include <string>

namespace upx_killer::engine::verification
{
    ExecutableVerificationResult ExecutableVerifier::Verify(
        std::filesystem::path const& executable,
        std::filesystem::path const& workingDirectory,
        std::uint32_t timeoutMilliseconds) noexcept
    {
        ExecutableVerificationResult result{};
        if (executable.empty() || timeoutMilliseconds == 0)
        {
            result.nativeError = ERROR_INVALID_PARAMETER;
            return result;
        }

        auto commandLine = executable.wstring();
        STARTUPINFOW startup{ sizeof(startup) };
        startup.dwFlags = STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION processInfo{};
        auto const previousErrorMode = SetErrorMode(
            SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        auto const created = CreateProcessW(
            executable.c_str(),
            commandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            workingDirectory.empty() ? nullptr : workingDirectory.c_str(),
            &startup,
            &processInfo);
        SetErrorMode(previousErrorMode);
        if (!created)
        {
            result.nativeError = GetLastError();
            return result;
        }

        auto const waitResult = WaitForSingleObject(processInfo.hProcess, timeoutMilliseconds);
        if (waitResult == WAIT_TIMEOUT)
        {
            result.timedOut = true;
            TerminateProcess(processInfo.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(processInfo.hProcess, 5000);
        }
        else if (waitResult == WAIT_OBJECT_0)
        {
            result.completed = true;
            DWORD exitCode{};
            if (GetExitCodeProcess(processInfo.hProcess, &exitCode)) result.exitCode = exitCode;
            else result.nativeError = GetLastError();
        }
        else
        {
            result.nativeError = GetLastError();
            TerminateProcess(processInfo.hProcess, ERROR_FUNCTION_FAILED);
            WaitForSingleObject(processInfo.hProcess, 5000);
        }
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return result;
    }
}
