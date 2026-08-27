#include <Windows.h>

int wmain()
{
    return IsDebuggerPresent() ? 0 : 1;
}
