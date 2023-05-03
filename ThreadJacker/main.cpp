#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <string>
#include <any>

extern "C" VOID Execute();

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

/*
struct HIJACKHISTORY
{
    HIJACKTYPE HijackType;
    UINT_PTR FunctionAddress;
    SIZE_T FunctionSize;

    bool operator==(HIJACKHISTORY& Other)
    {
        return (HijackType == Other.HijackType) &&
            (FunctionAddress == Other.FunctionAddress) &&
            (FunctionSize == Other.FunctionSize);
    }

    HIJACKDATA Data;
};
*/

HANDLE GetMainThreadHandle(DWORD TargetProcessPid)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 ThreadEntry = {};
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    Thread32First(hSnapshot, &ThreadEntry);
    do
    {
        Thread32Next(hSnapshot, &ThreadEntry);
    } while (ThreadEntry.th32OwnerProcessID != TargetProcessPid);

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, ThreadEntry.th32ThreadID);
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
    else if (TypeInfo == typeid(wchar_t*))
        return SizeType == SIZETYPE::INCLUDEEXTRA ? (sizeof(wchar_t*) + wcslen(*(const wchar_t**)&Type) * sizeof(WCHAR) + 1) : sizeof(wchar_t*);
    else
    {
        if (SizeType == SIZETYPE::ACTUALSIZE)
        {
            if (TypeName.find('*') != TypeName.npos)
                return sizeof(PVOID);
            else if (TypeInfo == typeid(int))
                return sizeof(int);
            else if (TypeInfo == typeid(short))
                return sizeof(short);
            else if (TypeInfo == typeid(bool))
                return sizeof(bool);
            // Floating point values must be handled by the xmm registers and I don't know how.
            //else if (TypeInfo == typeid(float))
            //  return sizeof(float);
            else
            {
                printf("[%s] Type couldn't be handled!\n", TypeName.c_str());
                return 0;
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
    static const BYTE ShellcodeBytes[] =
        "\x48\x83\xEC\x08\xC7\x04\x24\xCC\xCC\xCC\xCC\xC7\x44\x24\x04\xCC\xCC\xCC\xCC\x9C\x50\x51\x52\x53\x55\x56\x57"
        "\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48"
        "\x8B\x08\x48\x8B\x50\x08\x4C\x8B\x40\x10\x4C\x8B\x48\x18\x48\xB8\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xC4"
        "\x08\xFF\xD0\x48\x83\xEC\x08\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5E\x5D\x5B"
        "\x5A\x59\x58\x9D\xC3";

    static const PVOID ShellcodeMemory = VirtualAllocEx(TargetProcess, NULL, sizeof(ShellcodeBytes), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    static const BOOL WPMStatus = WriteProcessMemory(TargetProcess, ShellcodeMemory, ShellcodeBytes, sizeof(ShellcodeBytes), NULL);

    // Getting a snapshot of the threads running on the system.
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 ThreadEntry = {};
    ThreadEntry.dwSize = sizeof(THREADENTRY32);

    // Iterating through the threads until we find a thread from the target process.
    Thread32First(hSnapshot, &ThreadEntry);
    while (ThreadEntry.th32OwnerProcessID != GetProcessId(TargetProcess))
    {
        if (!Thread32Next(hSnapshot, &ThreadEntry))
        {
            printf("Thread32Next failed, err: 0x%X\n", GetLastError());

            CloseHandle(hSnapshot);
            return;
        }
    }

    CloseHandle(hSnapshot);

    // Getting a handle to the found thread.
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadEntry.th32ThreadID);
    if (!hThread)
    {
        printf("OpenThread failed, err: 0x%X\n", GetLastError());
        return;
    }

    // Setting up a CONTEXT structure to be used while getting the thread context, CONTEXT_CONTROL meaning
    // we will only work on RIP, etc.
    CONTEXT ThreadContext;
    ThreadContext.ContextFlags = CONTEXT_CONTROL;

    // Suspending the thread because if we change the thread context while it's running it can result in undefined behaviour.
    if (SuspendThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
    {
        printf("SuspendThread failed, err: 0x%X\n", GetLastError());
        CloseHandle(hThread);
        return;
    }

    // Getting the thread context.
    if (GetThreadContext(hThread, &ThreadContext))
    {
        // Saving the RIP since we are gonna return the thread after the shellcode is executed.
        UINT_PTR JmpBackAddr = ThreadContext.Rip;

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
        // corresponding bytes ( CC ) which gets moved into rax and the shellcode uses rax as the base for the function address.
        Buffer64 = Data.FunctionAddress;
        WriteProcessMemory(TargetProcess, (LPVOID)((BYTE*)ShellcodeMemory + 70), &Buffer64, sizeof(DWORD64), NULL);

        // Updating the RIP to ShellcodeAddress
#ifdef _WIN64
        ThreadContext.Rip = (DWORD64)ShellcodeMemory;
#else
        ThreadContext.Eip = ShellcodeAddress;
        ThreadContext.Ecx = ShellcodeAddress;
#endif

        // Setting the updated thread context.
        if (!SetThreadContext(hThread, &ThreadContext))
            printf("SetThreadContext failed, err: 0x%X\n", GetLastError());
    }
    else
        printf("GetThreadContext failed, err: 0x%X\n", GetLastError());

    // Resuming the thread with the updated RIP making the shellcode get executed IF the thread was already in a execute state when it was suspended,
    // if not, the thread will stay in it's suspend state.
    if (ResumeThread(hThread) == HandleToULong(INVALID_HANDLE_VALUE))
    {
        printf("ResumeThread failed, err: 0x%X\n", GetLastError());
        return;
    }

    return;
}

void HandleHijack(HANDLE TargetProcess, HIJACKTYPE HijackType, UINT_PTR FunctionAddress, SIZE_T FunctionSize, std::vector<std::any> Arguments = {})
{
    /*
    static std::vector<HIJACKHISTORY> History;

    bool AllocateFunction = true;
    HIJACKHISTORY CurrentHistory = { HijackType, FunctionAddress, FunctionSize };
    for (auto& IdxHistory : History)
    {
        if (CurrentHistory == IdxHistory)
        {
            CurrentHistory = IdxHistory;

            AllocateFunction = false;
            break;
        }
    }
    */
    HIJACKDATA Data = {};

    PVOID VariablesMemory = nullptr;

    const SIZE_T ArgumentsSize = GetArgumentsSize(Arguments, SIZETYPE::INCLUDEEXTRA);
    const SIZE_T OffsetToExtra = GetArgumentsSize(Arguments, SIZETYPE::DEFAULT);

    VariablesMemory = VirtualAllocEx(TargetProcess, nullptr, ArgumentsSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!VariablesMemory)
    {
        printf("[!] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
        return;
    }

    const std::vector<BYTE> ZeroBytes(ArgumentsSize, 0);
    if (!WriteProcessMemory(TargetProcess, VariablesMemory, &ZeroBytes.at(0), ZeroBytes.size(), NULL))
    {
        printf("[!] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
        VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
        return;
    }

    SIZE_T Offset = 0;
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
                printf("[!] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
                return;
            }
        }
        else
        {
            const SIZE_T ActualSize = GetTypeSize(ArgIdx, SIZETYPE::ACTUALSIZE);
            if (!WriteProcessMemory(TargetProcess, (BYTE*)VariablesMemory + Offset, &ArgIdx, ActualSize, NULL))
            {
                printf("[!] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                VirtualFreeEx(TargetProcess, VariablesMemory, 0, MEM_RELEASE);
                return;
            }
        }

        Offset += IsString ? sizeof(PVOID) : ArgSize;
        OffsetFromExtra += StringSize;
    }

    //CurrentHistory.Data.VariablesAddress = (UINT_PTR)VariablesMemory;
    Data.VariablesAddress = (UINT_PTR)VariablesMemory;

    PVOID AllocatedMemory = nullptr;
    /*
    if (AllocateFunction)
    {
    */
        switch (HijackType)
        {
        case HIJACKTYPE::DIRECT:
        {
            //CurrentHistory.Data.FunctionAddress = FunctionAddress;
            Data.FunctionAddress = FunctionAddress;

            //HijackThread(TargetProcess, CurrentHistory.Data);
            HijackThread(TargetProcess, Data);

            break;
        }
        case HIJACKTYPE::BYTE:
        {
            std::vector<BYTE>* FunctionBytes = (std::vector<BYTE>*)FunctionAddress;
            AllocatedMemory = VirtualAllocEx(TargetProcess, nullptr, FunctionBytes->size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (!AllocatedMemory)
            {
                printf("[!] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
                return;
            }

            if (!WriteProcessMemory(TargetProcess, AllocatedMemory, FunctionBytes, FunctionBytes->size(), NULL))
            {
                printf("[!] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                VirtualFreeEx(TargetProcess, AllocatedMemory, 0, MEM_RELEASE);
                return;
            }
        }
        case HIJACKTYPE::SELF:
        {
            if (!AllocatedMemory)
            {
                UINT_PTR* FunctionAndSize = (UINT_PTR*)FunctionAddress;

                AllocatedMemory = VirtualAllocEx(TargetProcess, nullptr, FunctionAndSize[1], MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                if (!AllocatedMemory)
                {
                    printf("[!] VirtualAllocEx failed, err: 0x%X\n", GetLastError());
                    return;
                }

                if (!WriteProcessMemory(TargetProcess, AllocatedMemory, (PVOID)FunctionAndSize[0], FunctionAndSize[1], NULL))
                {
                    printf("[!] WriteProcessMemory failed, err: 0x%X\n", GetLastError());
                    VirtualFreeEx(TargetProcess, AllocatedMemory, 0, MEM_RELEASE);
                    return;
                }
            }

            //CurrentHistory.Data.FunctionAddress = (UINT_PTR)AllocatedMemory;
            Data.FunctionAddress = (UINT_PTR)AllocatedMemory;
            //HijackThread(TargetProcess, CurrentHistory.Data);
            HijackThread(TargetProcess, Data);

            break;
        }
        }
    /*
    }
    else
        HijackThread(TargetProcess, CurrentHistory.Data);
    */

    printf("Press any key to free memory.\n");
    getchar();

    if (Data.FunctionAddress)
        VirtualFreeEx(TargetProcess, (LPVOID)Data.FunctionAddress, 0, MEM_RELEASE);

    if (Data.VariablesAddress)
        VirtualFreeEx(TargetProcess, (LPVOID)Data.VariablesAddress, 0, MEM_RELEASE);
}

int main(int argc, const char* argv[])
{
    // Checking for arguments.
    if (argc != 2)
    {
        std::string Filename = argv[0];
        printf("Invalid arguments\nUsage: %s PID\n", Filename.substr(Filename.find_last_of("/\\") + 1).c_str());
        return 0;
    }

    // Converting string pid to integer pid.
    DWORD Pid = atoi(argv[1]);
    if (!Pid)
    {
        printf("Invalid PID\n");
        return 0;
    }

    // Getting a handle to the target process so we can access it.
    HANDLE TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    if (!TargetProcess)
    {
        printf("[!] OpenProcess failed. Err code: 0x%X\n", GetLastError());
        return 0;
    }
    printf("[*] Retrieved handle for target process, 0x%X\n", HandleToULong(TargetProcess));

    HandleHijack(TargetProcess, HIJACKTYPE::DIRECT, (UINT_PTR)MessageBoxA, 0, { 0, "TEXT", "CAPTION", 0});

    return 0;
}