#include <iostream>
#include <unex-filter/filter.h>

struct TestStruct
{
    __declspec(noinline) static void Crash(void *by)
    {
        // Crash(by);

        // asm(".byte 0xC4");
        *(void **)0x2328 = by;
    }
};

#include <windows.h>
// #include <ulib/format.h>
// #include <dbghelp.h>
int hello_nigger = 20000;

__declspec(noinline) size_t Plak(size_t val)
{
    if (val == 0x400)
        Sleep(1);

    if (val == 0x300)
        return 0;

    return Plak(0x200 + val * 20) + Plak(val) - Plak(val * 2);
}

LONG ExceptionHandler(EXCEPTION_POINTERS *ExceptionInfo)
{
    printf("hello vectored\n");
    return 0;
}

int main()
{
    // AddVectoredExceptionHandler(0, ExceptionHandler);

    unex::setup_filter();
    Plak(rand());
    TestStruct::Crash((void *)&hello_nigger);

    // GetSystemTime((LPSYSTEMTIME)0x400);

    return 0;
}
