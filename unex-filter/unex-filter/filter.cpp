#include "filter.h"
#include <windows.h>

#include <ulib/format.h>
#include <ulib/runtimeerror.h>

#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

#include <winternl.h>

#include <pelib/pelib.h>
#include <futile/futile.h>

namespace unex
{
    static bool gIsSymbolsInitialized = false;

    bool InitializeSymbols() { return SymInitialize(GetCurrentProcess(), NULL, TRUE); }

    struct SymbolInfo
    {
        ulib::u8string name;
        void *addr;
    };

    std::optional<SymbolInfo> GetSymbolInfo(void *addr)
    {
        HANDLE hProcess = GetCurrentProcess();

        DWORD64 dwDisplacement = 0;
        DWORD64 dwAddress = DWORD64(addr);

        char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        if (SymFromAddr(hProcess, dwAddress, &dwDisplacement, pSymbol))
        {
            SymbolInfo info;
            info.addr = (void *)pSymbol->Address;
            info.name = (typename ulib::u8string::CharT *)pSymbol->Name;

            return info;
        }
        else
        {
            return std::nullopt;
        }
    }

    inline ulib::u8string FormatNtStatus(NTSTATUS nsCode)
    {
        // Get handle to ntdll.dll.
        HMODULE hNtDll = LoadLibraryW(L"NTDLL.DLL");

        // Check for fail, user may use GetLastError() for details.
        if (hNtDll == NULL)
            return "";

        LPWSTR messageBuffer = nullptr;
        size_t size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                         FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_HMODULE,
                                     hNtDll, RtlNtStatusToDosError(nsCode), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                     (LPWSTR)&messageBuffer, 0, NULL);

        FreeLibrary(hNtDll);

        if (size <= 2)
            return ulib::format(u8"[0x{:X}] -> \"{}\"", DWORD(nsCode), "Unknown NTSTATUS Code");

        ulib::wstring message(messageBuffer, size - 2);
        LocalFree(messageBuffer);

        return ulib::format(u8"[0x{:X}] -> \"{}\"", DWORD(nsCode), message);
    }

    ulib::wstring GetModulePath(HMODULE hModule)
    {
        WCHAR wcfilename[MAX_PATH] = {0};
        GetModuleFileNameW(hModule, wcfilename, MAX_PATH);
        ulib::wstring filepath = wcfilename;
        return filepath;
    }

    ulib::wstring_view GetModuleName(ulib::wstring_view filepath)
    {
        ulib::wstring_view filename = filepath;
        auto idx = filepath.rfind(L'\\');
        if (idx != ulib::npos)
            filename = ulib::wstring_view{filepath.begin() + idx + 1, filepath.end()};
        return filename;
    }

    ulib::wstring GetModuleName(HMODULE hModule)
    {
        ulib::wstring filepath = GetModulePath(hModule);
        return GetModuleName(filepath);
    }

    void GetModulePathName(HMODULE hModule, ulib::wstring &path, ulib::wstring &name)
    {
        path = GetModulePath(hModule);
        name = GetModuleName(path);
    }

    ulib::string FormatAddress(void *address)
    {
        HMODULE hModule = (HMODULE)SymGetModuleBase64(GetCurrentProcess(), (DWORD64)address);
        ulib::wstring moduleName = GetModuleName(hModule);
        return ulib::format("({}+0x{:X})", moduleName, (uintptr_t)((uintptr_t)address - (uintptr_t)hModule));
    }

    ulib::string FormatSymbol(void *address)
    {
        if (auto symbolInfo = GetSymbolInfo(address))
        {
            return ulib::format("[{}+0x{:X}]", symbolInfo->name, (uintptr_t)address - (uintptr_t)symbolInfo->addr);
        }

        return "";
    }

    struct RegisterInfo
    {
        ulib::string name;
        uintptr_t value;
    };

    class RegistersInfo
    {
    public:
        void Reg(ulib::string_view name, uintptr_t value) { mRegisters.push_back(RegisterInfo{name, value}); }

        void AlignRegs()
        {
            for (auto &reg : mRegisters)
                if (reg.name.length() < 3)
                    reg.name = ulib::str(" ") + reg.name;
        }

        ulib::string DumpRegs(size_t split = 4)
        {
            AlignRegs();

            size_t placed = 0;
            ulib::string result;
            for (auto &reg : mRegisters)
            {
                if (placed == split)
                {
                    result += "\n";
                    placed = 0;
                }

                result += ulib::format("{} = 0x{:016X} | ", reg.name, reg.value);
                placed++;
            }

            return result + "\n";
        }

        ulib::string DumpRegsWithSymbols()
        {
            ulib::string result;
            for (auto &reg : mRegisters)
            {
                if (GetSymbolInfo((void *)reg.value))
                    result += ulib::format("{} = 0x{:016X} {} {}\n", reg.name, reg.value,
                                           FormatSymbol((void *)reg.value), FormatAddress((void *)reg.value));
            }

            return result;
        }

        bool IsAllRegsWithSymbols()
        {
            for (auto &reg : mRegisters)
            {
                if (!GetSymbolInfo((void *)reg.value))
                    return false;
            }

            return true;
        }

        bool HasRegsWithSymbols()
        {
            for (auto &reg : mRegisters)
            {
                if (GetSymbolInfo((void *)reg.value))
                    return true;
            }

            return false;
        }

        size_t Count() { return mRegisters.size(); }

    private:
        ulib::list<RegisterInfo> mRegisters;
    };

    std::optional<uintptr_t> GetPEFileImageBase(const futile::fs::path &path)
    {
        try
        {
            ulib::buffer data = futile::open(path).read<ulib::buffer>();
            pelib::Image64 image{data.data()};

            return uintptr_t(image.GetNtHeaders()->OptionalHeader64.ImageBase);
        }
        catch (...)
        {
        }

        return std::nullopt;
    }

    ulib::string FormatRegister(ulib::string_view name, uintptr_t reg) { return ulib::format("{} = 0x{:016X}"); }

    void AppendRegsToText(ulib::string &text, RegistersInfo &regs, size_t split = 4)
    {
        if (regs.Count() == 1)
        {
            if (regs.IsAllRegsWithSymbols())
                text += regs.DumpRegsWithSymbols() + "\n";
            else
                text += regs.DumpRegs(1) + "\n";
        }
        else
        {
            text += regs.DumpRegs(split) + "\n";
            if (regs.HasRegsWithSymbols())
                text += regs.DumpRegsWithSymbols() + "\n";
        }
    }

    void RealFilterCallback(EXCEPTION_POINTERS *ExceptionInfo)
    {
        ulib::string text;
        text.append("[unex-filter]: Detected unhandled exception:\n");

        if (ExceptionInfo)
        {
            if (PEXCEPTION_RECORD pExceptionRecord = ExceptionInfo->ExceptionRecord)
            {
                PVOID address = pExceptionRecord->ExceptionAddress;
                DWORD code = pExceptionRecord->ExceptionCode;
                DWORD flags = pExceptionRecord->ExceptionFlags;

                HMODULE hModule = (HMODULE)SymGetModuleBase64(GetCurrentProcess(), (DWORD64)address);
                ULONGLONG imageBase = pelib::Image{hModule}.GetNtHeaders()->OptionalHeader64.ImageBase;

                ulib::wstring filepath, filename;
                GetModulePathName(hModule, filepath, filename);

                auto symbolInfo = GetSymbolInfo(address);
                uintptr_t offset = uintptr_t(address) - uintptr_t(hModule);

                text += ulib::format("Exception: {}\n", FormatNtStatus(code), imageBase);
                text += ulib::format("Address: 0x{:X} ({}+0x{:X}) {}\n", (uintptr_t)address, filename, offset,
                                     FormatSymbol(address));
                text += ulib::format("Address with 0x140000000 base: 0x{:X}\n", 0x140000000 + offset);
                text += ulib::format("Flags: 0x{:X}\n\n", flags);

                text += ulib::format("Module Base: 0x{:X}\n", (UINT_PTR)hModule);
                text += ulib::format("Module Path: \"{}\"\n", filepath);

                text += "\n";
            }

            if (PCONTEXT ctx = ExceptionInfo->ContextRecord)
            {
                {
                    RegistersInfo regs;
                    regs.Reg("Rax", ctx->Rax);
                    regs.Reg("Rcx", ctx->Rcx);
                    regs.Reg("Rdx", ctx->Rdx);
                    regs.Reg("Rbx", ctx->Rbx);
                    regs.Reg("Rsp", ctx->Rsp);
                    regs.Reg("Rbp", ctx->Rbp);
                    regs.Reg("Rsi", ctx->Rsi);
                    regs.Reg("Rdi", ctx->Rdi);
                    regs.Reg("R8", ctx->R8);
                    regs.Reg("R9", ctx->R9);
                    regs.Reg("R10", ctx->R10);
                    regs.Reg("R11", ctx->R11);
                    regs.Reg("R12", ctx->R12);
                    regs.Reg("R13", ctx->R13);
                    regs.Reg("R14", ctx->R14);
                    regs.Reg("R15", ctx->R15);

                    AppendRegsToText(text, regs, 4);
                }

                {
                    RegistersInfo regs1;
                    regs1.Reg("Rip", ctx->Rip);

                    text.pop_back();
                    AppendRegsToText(text, regs1, 1);
                }

                {
                    RegistersInfo home;
                    home.Reg("P1Home", ctx->P1Home);
                    home.Reg("P2Home", ctx->P2Home);
                    home.Reg("P3Home", ctx->P3Home);
                    home.Reg("P4Home", ctx->P4Home);
                    home.Reg("P5Home", ctx->P5Home);
                    home.Reg("P6Home", ctx->P6Home);

                    AppendRegsToText(text, home, 3);
                }

                // {
                //     RegistersInfo regs;
                //     regs.Reg("ContextFlags", ctx->ContextFlags);
                //     regs.Reg("MxCsr", ctx->MxCsr);

                //     AppendRegsToText(text, regs, 3);
                // }

                // {

                //     RegistersInfo regs;
                //     regs.Reg("SegCs", ctx->SegCs);
                //     regs.Reg("SegDs", ctx->SegDs);
                //     regs.Reg("SegEs", ctx->SegEs);
                //     regs.Reg("SegFs", ctx->SegFs);
                //     regs.Reg("SegGs", ctx->SegGs);
                //     regs.Reg("SegSs", ctx->SegSs);
                //     regs.Reg("EFlags", ctx->EFlags);

                //     AppendRegsToText(text, regs, 3);
                // }

                // {

                //     RegistersInfo regs;
                //     regs.Reg("Dr0", ctx->Dr0);
                //     regs.Reg("Dr1", ctx->Dr1);
                //     regs.Reg("Dr2", ctx->Dr2);
                //     regs.Reg("Dr3", ctx->Dr3);
                //     regs.Reg("Dr6", ctx->Dr6);
                //     regs.Reg("Dr7", ctx->Dr7);

                //     AppendRegsToText(text, regs, 3);
                // }

                // {
                //     RegistersInfo regs;
                //     for (size_t i = 0; i != 16; i++)
                //     {
                //         auto &xmm = ctx->FltSave.XmmRegisters[i];
                //         regs.Reg(ulib::format("xmm{}_High", i), (uintptr_t)xmm.High);
                //         regs.Reg(ulib::format("xmm{}_Low", i), (uintptr_t)xmm.Low);
                //     }

                //     AppendRegsToText(text, regs, 2);
                // }

                // {
                //     RegistersInfo regs;
                //     regs.Reg("DebugControl", ctx->DebugControl);
                //     regs.Reg("LastBranchToRip", ctx->LastBranchToRip);
                //     regs.Reg("LastBranchFromRip", ctx->LastBranchFromRip);
                //     regs.Reg("LastExceptionToRip", ctx->LastExceptionToRip);
                //     regs.Reg("LastExceptionFromRip", ctx->LastExceptionFromRip);

                //     AppendRegsToText(text, regs, 3);
                // }
            }
        }

        fmt::print("{}\n", text);
    }

    void* gTempStack;
    void* gPrevStack = nullptr;
    LPVOID gFilterFiber = nullptr;
    EXCEPTION_POINTERS * gExceptionInfo;

    void FilterFiber(void* data)
    {
        RealFilterCallback(gExceptionInfo);
    }

    void RunCallbackUnderFiber()
    {
        ConvertThreadToFiber(NULL);
        SwitchToFiber(gFilterFiber);
    }

    __attribute__((naked)) LONG WINAPI FilterCallback(EXCEPTION_POINTERS *ExceptionInfo)
    {
        asm
        {
            mov gExceptionInfo, rcx
            add rsp, 0x100
            jmp RunCallbackUnderFiber
        }
    }

    char gBuffer[0x4000];
    void setup_filter()
    {
        if (!gIsSymbolsInitialized)
        {
            gFilterFiber = CreateFiber(0x8000, FilterFiber, NULL);
            SetUnhandledExceptionFilter(FilterCallback);

            if (InitializeSymbols())
            {
                gIsSymbolsInitialized = true;
            }
            else
            {
                throw ulib::RuntimeError{"[unex-filter] Failed to initialize symbols"};
            }
        }
    }
} // namespace unex