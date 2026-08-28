#include <Windows.h>

int wmain()
{
    static volatile BOOL debuggerObserved{};
    debuggerObserved = IsDebuggerPresent();
    return 0;
}
