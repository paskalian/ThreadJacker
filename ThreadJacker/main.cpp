#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <any>

#ifdef _WIN64
extern "C" VOID Execute64();
#else
extern "C" VOID Execute32();
#endif

#define HIDWORD(x) (x >> 32)
#define LODWORD(x) (x & 0xFFFFFFFF)

enum class HIJACKTYPE
{
    DIRECT, // ExecuteAddress is treated as is in the target process address space, there will be no extra allocations other than for the Arguments. After the set-up,
            // it gets executed.

    SELF,   // ExecuteAddress is treated as an array of 2 UINT_PTRs which the first UINT_PTR being the function address (in the current process), and the second being the
            // function size, which then the function size is used to allocate memory for the function itself and copy it to there from the function address + the Arguments
            // inside the target process. Finally after the set-up, it gets executed.

    BYTE    // ExecuteAddress is treated as an std::vector<BYTE>* which is used to allocate an extra memory for the function itself and copy it to there + the Arguments
            // inside the target process. Finally after the set-up, it gets executed.
};

struct HIJACKDATA
{
    UINT_PTR FunctionAddress = 0;
    UINT_PTR VariablesAddress = 0;
};

HANDLE GetMainThreadHandle(DWORD TargetProcessPid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 ThreadEntry = {};
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    // Putting an iteration limit to prevent deadlock.
    SIZE_T IterateTimes = 0;
    Thread32First(hSnapshot, &ThreadEntry);
    do
    {
        Thread32Next(hSnapshot, &ThreadEntry);

        IterateTimes++;
        if (IterateTimes >= 10000)
        {
            printf("[-] Thread couldn't be found.\n");
            CloseHandle(hSnapshot);
            return NULL;
        }
    } while (ThreadEntry.th32OwnerProcessID != TargetProcessPid);

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
    if (!hThread)
        printf("OpenThread failed, err: 0x%X\n", GetLastError());

    CloseHandle(hSnapshot);

    return hThread;
}

enum class SIZETYPE
{
    DEFAULT,
    INCLUDEEXTRA,
    ACTUALSIZE
};

SIZE_T GetTypeSize(const std::any& Type, SIZETYPE SizeType)
{
    const type_info& TypeInfo = Type.type();
    const std::string TypeName = TypeInfo.name();

    // I can't switch.
    if (TypeInfo == typeid(const char*) || TypeInfo == typeid(char*))
        return SizeType == SIZETYPE::INCLUDEEXTRA ? (sizeof(char*) + strlen(*(const char**)&Type) + 1) : sizeof(char*);
    else if (TypeInfo == typeid(const wchar_t*))
        return SizeType == SIZETYPE::INCLUDEEXTRA ? (sizeof(wchar_t*) + wcslen(*(const wchar_t**)&Type) * sizeof(WCHAR) + 2) : sizeof(wchar_t*);
    else
    {
        if (SizeType == SIZETYPE::ACTUALSIZE)
        {
            if (TypeName.find('*') != TypeName.npos)
                return sizeof(PVOID);
            else if (TypeInfo == typeid(int))
                return sizeof(int);
            else if (TypeInfo == typeid(long))
                return sizeof(long);
            else if (TypeInfo == typeid(short))
                return sizeof(short);
            else if (TypeInfo == typeid(bool))
                return sizeof(bool);
            // Floating point values must be handled by the xmm registers and I don't know how.
            //else if (TypeInfo == typeid(float))
            //  return sizeof(float);
            else
            {
                printf("[-] Type (%s) couldn't be handled!\n", TypeName.c_str());
                assert(false);
            }
        }

        return sizeof(PVOID);
    }
}

SIZE_T GetArgumentsSize(const std::vector<std::any>& Arguments, SIZETYPE SizeType)
{
    SIZE_T ArgumentsSize = 0;
    for (auto& ArgIdx : Arguments)
        ArgumentsSize += GetTypeSize(ArgIdx, SizeType);

    return ArgumentsSize;
}

void HijackThread(HANDLE TargetProcess, HIJACKDATA& Data)
{
    printf("[*] Hijacking the thread with current info:\n  [*] Function Address: %p\n  [*] Variables Address: %p\n", (PVOID)Data.FunctionAddress, (PVOID)Data.VariablesAddress);

#ifdef _WIN64
    static const BYTE ShellcodeBytes[] =
        "\x48\x83\xEC\x08\xC7\x04\x24\xCC\xCC\xCC\xCC\xC7\x44\x24\x04\xCC\xCC\xCC\xCC\x9C\x50\x51\x52\x53\x55\x56\x57\x41\x50\x41\x51\x41\x52"
        "\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\x30\x48\x8B\x48\x08\x48\x8B\x50\x10\x4C\x8B"
        "\x40\x18\x4C\x8B\x48\x20\x48\x33\xDB\x48\x89\x18\x48\x83\xFE\x04\x76\x20\x48\x83\xEE\x04\x48\x89\x30\x48\xF7\xC6\x01\x00\x00\x00\x74"
        "\x04\x48\x83\xEC\x08\xFF\x74\xF0\x20\x48\xFF\xCE\x48\x85\xF6\x75\xF4\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x20\xFF\xD0"
        "\x48\x83\xC4\x20\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8B\x30\x48\x8B\xDE\x48\x6B\xF6\x08\x48\x03\xE6\x48\xF7\xC3\x01\x00\x00"
        "\x00\x74\x04\x48\x83\xC4\x08\x48\xC7\x00\xFF\xFF\xFF\xFF\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D"
        "\x5B\x5A\x59\x58\x9D\xC3";
#else
    static const BYTE ShellcodeBytes[] =
        "\x83\xEC\x04\xC7\x04\x24\xCC\xCC\xCC\xCC\x9C\x60\xB8\xCC\xCC\xCC\xCC\x8B\x30\x8B\x58\x04\x83\xFB\x02\x74\x0B\xFF\x74\xB0\x04\x4E\x85"
        "\xF6\x75\xF7\xEB\x1F\x8B\x48\x08\x8B\x50\x0C\xC7\x00\x00\x00\x00\x00\x83\xFE\x02\x76\x0E\x83\xEE\x02\x89\x30\xFF\x74\xB0\x0C\x4E\x85"
        "\xF6\x75\xF7\xB8\xCC\xCC\xCC\xCC\xFF\xD0\xB8\xCC\xCC\xCC\xCC\x8B\x30\x8B\x58\x04\x85\xDB\x75\x05\x6B\xF6\x04\x03\xE6\xC7\x00\xFF\xFF"
        "\xFF\xFF\x61\x9D\xC3";
#endif

    const PVOID ShellcodeMemory = VirtualAllocEx(TargetProcess, NULL, sizeof(ShellcodeBytes), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!ShellcodeMemory)
    {
        printf("[-] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
        return;
    }
    printf("[*] Allocated memory for shellcode [%p]\n", ShellcodeMemory);

    if (!WriteProcessMemory(TargetProcess, ShellcodeMemory, ShellcodeBytes, sizeof(ShellcodeBytes), NULL))
    {
        printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());

        VirtualFreeEx(TargetProcess, ShellcodeMemory, 0, MEM_RELEASE);
        return;
    }
    printf("[*] Shellcode bytes are written.\n");

    // Getting a handle to the main thread.
    HANDLE hThread = GetMainThreadHandle(GetProcessId(TargetProcess));
    if (!hThread)
    {
        printf("[-] OpenThread failed, err: 0x%X\n", GetLastError());

        VirtualFreeEx(TargetProcess, ShellcodeMemory, 0, MEM_RELEASE);
        return;
    }
    printf("[*] Retrieved handle for target thread, 0x%X\n", HandleToULong(hThread));

    // Setting up a CONTEXT structure to be used while getting the thread context, CONTEXT_CONTROL meaning
    // we will only work on RIP, etc.
    CONTEXT ThreadContext;
    ThreadContext.ContextFlags = CONTEXT_CONTROL;

    // Suspending the thread because if we change the thread context while it's running it can result in undefined behaviour.
    if (SuspendThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
    {
        printf("[-] SuspendThread failed, err: 0x%X\n", GetLastError());

        VirtualFreeEx(TargetProcess, ShellcodeMemory, 0, MEM_RELEASE);
        CloseHandle(hThread);
        return;
    }
    printf("[*] Thread suspended.\n");

    // Getting the thread context.
    if (GetThreadContext(hThread, &ThreadContext))
    {
        // Saving the RIP since we are gonna return the thread after the shellcode is executed.
#ifdef _WIN64
        UINT_PTR JmpBackAddr = ThreadContext.Rip;
#else
        UINT_PTR JmpBackAddr = ThreadContext.Eip;
#endif

#ifdef _WIN64
        DWORD LoJmpBk = LODWORD(JmpBackAddr);
        DWORD HiJmpBk = HIDWORD(JmpBackAddr);

        // Writing the JmpBackAddr into the
        // mov dword ptr [rsp], 0CCCCCCCCh
        // mov dword ptr[rsp + 4], 0CCCCCCCCh
        // corresponding bytes ( CC ) and then when the shellcode is executed, it will get itself some stack space and write the
        // return address in there, when ret is called after all it pops the stack and returns to what was on top of
        // the stack which is that address.
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 7), &LoJmpBk, sizeof(DWORD), NULL);
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 15), &HiJmpBk, sizeof(DWORD), NULL);

        // Writing the ShellcodeParams into the
        // mov rax, 0CCCCCCCCCCCCCCCCh
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
        DWORD64 Buffer64 = Data.VariablesAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 45), &Buffer64, sizeof(DWORD64), NULL);

        // Writing the ShellcodeParams into the
        // mov rax, 0CCCCCCCCCCCCCCCCh
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the function address.
        Buffer64 = Data.FunctionAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 118), &Buffer64, sizeof(DWORD64), NULL);

        // Writing the ShellcodeParams into the
        // mov rax, 0CCCCCCCCCCCCCCCCh
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
        Buffer64 = Data.VariablesAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 138), &Buffer64, sizeof(DWORD64), NULL);
#else
        // We can directly write JmpBackAddr since it will be a DWORD.

        // Writing the JmpBackAddr into the
        // mov dword ptr [esp], 0CCCCCCCCh
        // corresponding bytes ( CC ) and then when the shellcode is executed, it will get itself some stack space and write the
        // return address in there, when ret is called after all it pops the stack and returns to what was on top of
        // the stack which is that address.
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 6), &JmpBackAddr, sizeof(DWORD), NULL);

        // Writing the ShellcodeParams into the
        // mov eax, 0CCCCCCCCh
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
        DWORD Buffer = Data.VariablesAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 13), &Buffer, sizeof(DWORD), NULL);

        // Writing the ShellcodeParams into the
        // mov eax, 0CCCCCCCCh
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
        Buffer = Data.FunctionAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 70), &Buffer, sizeof(DWORD), NULL);

        // Writing the ShellcodeParams into the
        // mov eax, 0CCCCCCCCh
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the parameters.
        Buffer = Data.VariablesAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 77), &Buffer, sizeof(DWORD), NULL);
#endif

        printf("[*] Dummy bytes are overwritten.\n");

        // Updating the RIP to ShellcodeMemory
#ifdef _WIN64
        ThreadContext.Rip = (DWORD64)ShellcodeMemory;
#else
        ThreadContext.Eip = (DWORD32)ShellcodeMemory;
#endif

        // Setting the updated thread context.
        if (!SetThreadContext(hThread, &ThreadContext))
            printf("[-] SetThreadContext failed, err: 0x%X\n", GetLastError());
        else
            printf("[*] Thread context updated [RIP: %p -> %p].\n", (PVOID)JmpBackAddr, (PVOID)ShellcodeMemory);
    }
    else
        printf("[-] GetThreadContext failed, err: 0x%X\n", GetLastError());

    // Resuming the thread with the updated RIP making the shellcode get executed IF the thread was already in a execute state when it was suspended,
    // if not, the thread will stay in it's suspend state.
    if (ResumeThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
    {
        printf("[-] ResumeThread failed, err: 0x%X\n", GetLastError());

        VirtualFreeEx(TargetProcess, ShellcodeMemory, 0, MEM_RELEASE);
        CloseHandle(hThread);
        return;
    }
    printf("[*] Thread resumed.\n");

    CloseHandle(hThread);
    printf("[*] Target thread handle closed.\n");

    // Checking if our thread has finished.
    UINT_PTR ThreadFinish = 0;
    while (ReadProcessMemory(TargetProcess, (PVOID)Data.VariablesAddress, &ThreadFinish, sizeof(UINT_PTR), NULL), ThreadFinish != -1)
        ;

    // Giving the shellcode a little more time to finish.
    Sleep(50);

    printf("[*] Hijacked thread finished.\n");

    VirtualFreeEx(TargetProcess, ShellcodeMemory, 0, MEM_RELEASE);
    printf("[*] Shellcode memory released.\n");

    return;
}

enum class CALLINGCONVENTION : DWORD
{
    CC_CDECL,
    CC_STDCALL,
    CC_FASTCALL
};

void HandleHijack(HANDLE TargetProcess, HIJACKTYPE HijackType, UINT_PTR FunctionAddress, std::vector<std::any> Arguments = {}, CALLINGCONVENTION CallConvention = CALLINGCONVENTION::CC_CDECL)
{
    printf("==============================================\n");

#ifdef _WIN64
    // If the number of arguments is less than 4, we complete it to 4.
    while (Arguments.size() < 4)
        Arguments.push_back(0);
#else
    if (CallConvention == CALLINGCONVENTION::CC_FASTCALL)
    {
        // If the number of arguments is less than 2, we complete it to 2.
        while (Arguments.size() < 2)
            Arguments.push_back(0);
    }
#endif

    HIJACKDATA Data = {};

    PVOID VariablesMemory = nullptr;

    const SIZE_T ArgumentsSize = GetArgumentsSize(Arguments, SIZETYPE::INCLUDEEXTRA) + sizeof(DWORD64);
    const SIZE_T OffsetToExtra = GetArgumentsSize(Arguments, SIZETYPE::DEFAULT) + sizeof(DWORD64);

    // Allocating space for the argument count + arguments 
    VariablesMemory = VirtualAllocEx(TargetProcess, nullptr, ArgumentsSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!VariablesMemory)
    {
        printf("[-] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
        return;
    }
    printf("[*] Allocated memory for arguments [%p]\n", VariablesMemory);

    // Writing the argument count to the first UINT_PTR
    const SIZE_T ArgumentCount = Arguments.size();
    if (!WriteProcessMemory(TargetProcess, (BYTE*)VariablesMemory, &ArgumentCount, sizeof(SIZE_T), NULL))
    {
        printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
        VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
        return;
    }
#ifndef _WIN64
    // Writing the calling convetion to the second UINT_PTR
    if (!WriteProcessMemory(TargetProcess, (BYTE*)VariablesMemory + 4, &CallConvention, sizeof(DWORD), NULL))
    {
        printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
        VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
        return;
    }
#endif

    // Writing the other arguments, if it's a string we write them to the extra zone.
    SIZE_T Offset = sizeof(DWORD64);
    SIZE_T OffsetFromExtra = 0;
    for (auto& ArgIdx : Arguments)
    {
        const SIZE_T ArgSize = GetTypeSize(ArgIdx, SIZETYPE::INCLUDEEXTRA);

        const BOOLEAN IsString = ArgSize > sizeof(PVOID);
        const SIZE_T StringSize = IsString ? ArgSize - sizeof(PVOID) : 0;
        if (IsString)
        {
            BYTE* StringAddress = (BYTE*)VariablesMemory + OffsetToExtra + OffsetFromExtra;
            if (!WriteProcessMemory(TargetProcess, (BYTE*)VariablesMemory + Offset, &StringAddress, sizeof(PVOID), NULL) ||
               (!WriteProcessMemory(TargetProcess, StringAddress, *(const char**)&ArgIdx, StringSize, NULL)))
            {
                printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
                return;
            }
        }
        else
        {
            const SIZE_T ActualSize = GetTypeSize(ArgIdx, SIZETYPE::ACTUALSIZE);
            if (!WriteProcessMemory(TargetProcess, (BYTE*)VariablesMemory + Offset, &ArgIdx, ActualSize, NULL))
            {
                printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
                return;
            }
        }

        Offset += sizeof(PVOID);
        OffsetFromExtra += StringSize;
    }
    printf("[*] Arguments are written.\n");

    Data.VariablesAddress = (UINT_PTR)VariablesMemory;

    PVOID AllocatedMemory = nullptr;
    switch (HijackType)
    {
        case HIJACKTYPE::DIRECT:
        {
            // If it's direct we don't need to allocate then write the function since it's already in the target process.
            Data.FunctionAddress = FunctionAddress;

            HijackThread(TargetProcess, Data);

            break;
        }
        case HIJACKTYPE::BYTE:
        {
            // Allocating memory for the function in the target process and writing the function bytes there.
            std::vector<BYTE>* FunctionBytes = (std::vector<BYTE>*)FunctionAddress;
            AllocatedMemory = VirtualAllocEx(TargetProcess, nullptr, FunctionBytes->size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!AllocatedMemory)
            {
                printf("[-] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
                return;
            }
            printf("[*] Allocated memory for function [%p]\n", AllocatedMemory);

            if (!WriteProcessMemory(TargetProcess, AllocatedMemory, FunctionBytes, FunctionBytes->size(), NULL))
            {
                printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                VirtualFreeEx(TargetProcess, AllocatedMemory, 0, MEM_RELEASE);
                return;
            }
            printf("[*] Function bytes are written [%p]\n", AllocatedMemory);
        }
        case HIJACKTYPE::SELF:
        {
            // Since HIJACKTYPE::BYTE doesn't have a break it will end up here after it's own functionality, this check is to seperate the two because they end up doing the exact
            // same thing ultimately.
            if (!AllocatedMemory)
            {
                // Allocating memory for the function in the target process and writing the function bytes there.
                UINT_PTR* FunctionAndSize = (UINT_PTR*)FunctionAddress;

                AllocatedMemory = VirtualAllocEx(TargetProcess, nullptr, FunctionAndSize[1], MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                if (!AllocatedMemory)
                {
                    printf("[-] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
                    return;
                }
                printf("[*] Allocated memory for function [%p]\n", AllocatedMemory);

                if (!WriteProcessMemory(TargetProcess, AllocatedMemory, (PVOID)FunctionAndSize[0], FunctionAndSize[1], NULL))
                {
                    printf("[-] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                    VirtualFreeEx(TargetProcess, AllocatedMemory, 0, MEM_RELEASE);
                    return;
                }
                printf("[*] Function bytes are written [%p]\n", AllocatedMemory);
            }

            Data.FunctionAddress = (UINT_PTR)AllocatedMemory;
            HijackThread(TargetProcess, Data);

            break;
        }
    }

    if (HijackType != HIJACKTYPE::DIRECT)
    {
        if (Data.FunctionAddress)
            VirtualFreeEx(TargetProcess, (LPVOID)Data.FunctionAddress, 0, MEM_RELEASE);
        printf("[*] Function memory released.\n");
    }

    if (Data.VariablesAddress)
        VirtualFreeEx(TargetProcess, (LPVOID)Data.VariablesAddress, 0, MEM_RELEASE);
    printf("[*] Variables memory released.\n");

    printf("==============================================\n");
}

int main(int argc, const char* argv[])
{
    printf(R"(
  ________  ______  _________    ____         _____   ________ __ __________
 /_  __/ / / / __ \/ ____/   |  / __ \       / /   | / ____/ //_// ____/ __ \
  / / / /_/ / /_/ / __/ / /| | / / / /  __  / / /| |/ /   / ,<  / __/ / /_/ /
 / / / __  / _, _/ /___/ ___ |/ /_/ /  / /_/ / ___ / /___/ /| |/ /___/ _, _/
/_/ /_/ /_/_/ |_/_____/_/  |_/_____/   \____/_/  |_\____/_/ |_/_____/_/ |_|

                    made by github.com/paskalian                          
)");
    printf("\n");

    // Checking for arguments.
    if (argc != 2)
    {
        std::string Filename = argv[0];
        printf("[-] Invalid arguments\nUsage: %s PID\n", Filename.substr(Filename.find_last_of("/\\") + 1).c_str());
        return 0;
    }

    // Converting string pid to integer pid.
    DWORD Pid = atoi(argv[1]);
    if (!Pid)
    {
        printf("[-] Invalid PID\n");
        return 0;
    }

    // Getting a handle to the target process so we can access it.
    HANDLE TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (!TargetProcess)
    {
        printf("[-] OpenProcess failed. Err code: 0x%X\n", GetLastError());
        return 0;
    }
    printf("[*] Retrieved handle for target process, 0x%X\n", HandleToULong(TargetProcess));

    HandleHijack(TargetProcess, HIJACKTYPE::DIRECT, (UINT_PTR)MessageBoxExW, { 0, L"TEXT", L"CAPTION", 0, 0 }, CALLINGCONVENTION::CC_STDCALL);
    HandleHijack(TargetProcess, HIJACKTYPE::DIRECT, (UINT_PTR)MessageBoxW, { 0, L"WTEXT", L"WCAPTION", 0 }, CALLINGCONVENTION::CC_STDCALL);

    CloseHandle(TargetProcess);
    printf("[*] Target process handle closed.\n");

    return 0;
}