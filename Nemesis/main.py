#!/usr/bin/env python3
"""
Project Nemesis — a safe, educational network-security dashboard
Created for the software project course at Karaj Azad University.
Run with root privileges for attack modules to work.
"""

import os
import sys
import subprocess
import logging
import time
import threading
from pathlib import Path

VERSION = "3.0.0"
LOG_FILE = Path.home() / ".nemesis.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

SCRIPT_DIR = Path(__file__).resolve().parent
PIG_SCRIPT = SCRIPT_DIR / "DHCP" / "pig.py"
DNSFORGE_MODULE = "DNS"
ADSCAN_SCRIPT = SCRIPT_DIR / "AD" / "adscan.py"
GHOSTLOCK_SCRIPT = SCRIPT_DIR / "SMB" / "ghostlock.py"
SNIFFING_SCRIPT = SCRIPT_DIR / "sniffing" / "network_sniffer.py"
DOS_MODULE_DIR = SCRIPT_DIR / "Net"           # where 'src' package lives

# --- Startup checks ---
def check_tool(path, name):
    if not path.exists():
        sys.exit(f"ERROR: {name} not found at {path}.\n"
                 f"Make sure {name} is placed correctly.")

check_tool(PIG_SCRIPT, "pig.py")
check_tool(ADSCAN_SCRIPT, "adscan.py")
check_tool(GHOSTLOCK_SCRIPT, "ghostlock.py")
check_tool(SNIFFING_SCRIPT, "network_sniffer.py")

# DNS module
sys.path.insert(0, str(SCRIPT_DIR))
try:
    __import__(DNSFORGE_MODULE)
except ImportError:
    sys.exit(f"ERROR: {DNSFORGE_MODULE} module not found in {SCRIPT_DIR}\n"
             "Make sure dnsforge.py is inside the DNS folder.")

# DoS module (must be a package or module inside Net/)
dos_found = False
if (DOS_MODULE_DIR / "src.py").is_file():
    dos_found = True
elif (DOS_MODULE_DIR / "src" / "__init__.py").is_file():
    dos_found = True
elif (DOS_MODULE_DIR / "src" / "__main__.py").is_file():
    dos_found = True

if not dos_found:
    sys.exit(f"ERROR: DoS module not found in {DOS_MODULE_DIR / 'src'}\n"
             "Make sure the 'src' package (or module) is inside the 'Net' folder.")

class Colors:
    RED = "\033[1;31m"
    MUTED = "\033[0;31m"
    CYAN = "\033[1;36m"
    YELLOW = "\033[1;33m"
    GREEN = "\033[1;32m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    HLINE = "─"
    VLINE = "│"
    TOPL = "┌"
    TOPR = "┐"
    BOTL = "└"
    BOTR = "┘"

if not sys.stdout.isatty():
    for attr in dir(Colors):
        if not attr.startswith("_") and isinstance(getattr(Colors, attr), str):
            setattr(Colors, attr, "")
    Colors.HLINE = "-"
    Colors.VLINE = "|"
    Colors.TOPL = "+"
    Colors.TOPR = "+"
    Colors.BOTL = "+"
    Colors.BOTR = "+"

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")

def banner(text):
    width = 60
    print(f"{Colors.RED}{Colors.TOPL}{Colors.HLINE * (width - 2)}{Colors.TOPR}")
    pad = (width - 2 - len(text)) // 2
    print(f"{Colors.VLINE}{' ' * pad}{Colors.BOLD}{text}{Colors.RESET}{Colors.RED}"
          f"{' ' * (width - 2 - len(text) - pad)}{Colors.VLINE}")
    print(f"{Colors.BOTL}{Colors.HLINE * (width - 2)}{Colors.BOTR}{Colors.RESET}")

def logo():
    clear_screen()
    print(f"""{Colors.RED}
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
{Colors.RESET}""")
    print(f"{Colors.MUTED}               Windows Services Security Pentest Project{Colors.RESET}\n")

def pause():
    input(f"\n{Colors.MUTED}Press Enter to return...{Colors.RESET}")

def log_access(module):
    logging.info(module)

def confirm_attack(attack_desc):
    print(f"\n{Colors.RED}You are about to run:{Colors.RESET}")
    print(f"  {Colors.BOLD}{attack_desc}{Colors.RESET}")
    print(f"{Colors.RED}This requires root and must ONLY be done on authorised networks.{Colors.RESET}")
    answer = input(f"{Colors.CYAN}Type 'yes' to confirm: {Colors.RESET}").strip().lower()
    return answer in ("y", "yes", "yep", "yeah")

class InterfaceManager:
    def __init__(self):
        self._saved_iface = None

    def get_interface(self):
        if self._saved_iface:
            use = input(f"{Colors.CYAN}Use saved interface {Colors.BOLD}{self._saved_iface}"
                        f"{Colors.RESET}{Colors.CYAN}? [Y/n]: {Colors.RESET}").strip().lower()
            if use not in ("n", "no"):
                return self._saved_iface
        iface = input(f"{Colors.CYAN}Network interface (e.g. eth0, vboxnet0): {Colors.RESET}").strip()
        if iface:
            self._saved_iface = iface
            return iface
        return None

iface_mgr = InterfaceManager()

def run_command(cmd, attack_type, cwd=None):
    desc = " ".join(cmd)
    clear_screen()
    logo()
    banner(f"Execute {attack_type} Attack")
    print(f"\n{Colors.YELLOW}Command:{Colors.RESET}\n  {desc}")
    print(f"{Colors.GREEN}{'━' * 50}{Colors.RESET}")
    if not confirm_attack(desc):
        print(f"{Colors.MUTED}Attack cancelled.{Colors.RESET}")
        pause()
        return

    print(f"\n{Colors.CYAN}Launching attack...{Colors.RESET}")
    print(f"{Colors.MUTED}(Press Ctrl+C to stop){Colors.RESET}\n")

    try:
        if os.geteuid() != 0:
            subprocess.run(["sudo"] + cmd, cwd=cwd or str(SCRIPT_DIR))
        else:
            subprocess.run(cmd, cwd=cwd or str(SCRIPT_DIR))
    except KeyboardInterrupt:
        print(f"\n{Colors.MUTED}Attack interrupted by user.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")

    print(f"\n{Colors.GREEN}Attack finished.{Colors.RESET}")
    pause()

# ==================== DHCP Attacks ====================
class DHCPAttacks:
    @staticmethod
    def run(args):
        iface = DHCPAttacks._extract_iface(args)
        if not iface:
            iface = iface_mgr.get_interface()
            if not iface:
                print(f"{Colors.RED}No interface given, aborting.{Colors.RESET}")
                return
            args.extend(["-i", iface])
        else:
            iface_mgr._saved_iface = iface
        cmd = [str(PIG_SCRIPT)] + args
        run_command(cmd, "DHCP")

    @staticmethod
    def _extract_iface(args):
        try:
            idx = args.index("-i")
            return args[idx + 1]
        except (ValueError, IndexError):
            return None

    @staticmethod
    def quick_menu():
        while True:
            clear_screen(); logo(); banner("Quick DHCP Attack Profiles")
            print(f"""{Colors.YELLOW}
  [1] Basic exhaustion
  [2] Verbose exhaustion (v99)
  [3] Exhaustion + gratuitous ARP
  [4] Exhaustion + release neighbour IPs
  [5] Custom MAC list
  [6] DHCPv6 exhaustion
  [7] Fuzz mode
  [8] Multi-threaded (8 threads) + verbose
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": DHCPAttacks.run([])
            elif choice == "2": DHCPAttacks.run(["-v", "99"])
            elif choice == "3": DHCPAttacks.run(["-g"])
            elif choice == "4": DHCPAttacks.run(["-r"])
            elif choice == "5":
                macs = input(f"{Colors.CYAN}Enter MACs (comma separated): {Colors.RESET}").strip()
                if macs: DHCPAttacks.run(["-s", macs])
            elif choice == "6": DHCPAttacks.run(["-6"])
            elif choice == "7": DHCPAttacks.run(["-f"])
            elif choice == "8": DHCPAttacks.run(["-t", "8", "-v", "99"])
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen(); logo(); banner("Advanced DHCP Attack Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty for default.{Colors.RESET}\n")
        verb = input(f"{Colors.CYAN}Verbosity (0-99, default 10): {Colors.RESET}").strip()
        if verb: args.extend(["-v", verb])
        if input(f"{Colors.CYAN}IPv6 mode? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-6")
            if input(f"{Colors.CYAN}  RapidCommit? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("-1")
        macs = input(f"{Colors.CYAN}Custom MAC list (comma separated): {Colors.RESET}").strip()
        if macs: args.extend(["-s", macs])
        if input(f"{Colors.CYAN}Identical Ethernet & DHCP MAC? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("-S")
        req_opts = input(f"{Colors.CYAN}Custom request options (e.g. 21,22,23): {Colors.RESET}").strip()
        if req_opts: args.extend(["-O", req_opts])
        if input(f"{Colors.CYAN}Fuzzing? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("-f")
        threads = input(f"{Colors.CYAN}Threads (default 1): {Colors.RESET}").strip()
        if threads: args.extend(["-t", threads])
        for opt, flag in [("Show ARP who-has?", "-a"), ("Show ICMP requests?", "-i"),
                          ("Show lease options?", "-o"), ("Show lease confirmations?", "-l"),
                          ("Gratuitous ARP neighbor attack?", "-g"),
                          ("Release all neighbor IPs?", "-r"), ("ARP neighbor scan?", "-n")]:
            if input(f"{Colors.CYAN}{opt} [y/N]: {Colors.RESET}").strip().lower() == "y": args.append(flag)
        t_spawn = input(f"{Colors.CYAN}Thread spawn timeout (default 0.4): {Colors.RESET}").strip()
        if t_spawn: args.extend(["-x", t_spawn])
        t_dos = input(f"{Colors.CYAN}DOS timeout (default 8): {Colors.RESET}").strip()
        if t_dos: args.extend(["-y", t_dos])
        t_dhcp = input(f"{Colors.CYAN}DHCP request timeout (default 2): {Colors.RESET}").strip()
        if t_dhcp: args.extend(["-z", t_dhcp])
        if input(f"{Colors.CYAN}Colored output? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("-c")
        DHCPAttacks._final_review(args, lambda a: DHCPAttacks.run(a))

    @staticmethod
    def _final_review(args, run_func):
        while True:
            clear_screen(); logo(); banner("Final Command")
            print(f"{Colors.YELLOW}Current arguments:{Colors.RESET}")
            print(f"  {' '.join(args) if args else '(none)'}")
            print(f"\n{Colors.CYAN}[E]dit manually, [R]un, [A]bort: {Colors.RESET}")
            choice = input().strip().lower()
            if choice in ("e", "edit"):
                new_args = input(f"{Colors.CYAN}Enter replacement arguments: {Colors.RESET}").strip().split()
                if new_args: args.clear(); args.extend(new_args)
            elif choice in ("r", "run"): run_func(args); return
            elif choice in ("a", "abort"): print(f"{Colors.MUTED}Wizard cancelled.{Colors.RESET}"); pause(); return
            else: print(f"{Colors.RED}Invalid choice.{Colors.RESET}")

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments: {Colors.RESET}").strip()
        if raw: DHCPAttacks.run(raw.split())
        else: print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("DHCP Attack Lab")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw pig.py arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": DHCPAttacks.quick_menu()
            elif choice == "2": DHCPAttacks.advanced_wizard()
            elif choice == "3": DHCPAttacks.raw_args()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== DNS Attacks ====================
class DNSAttacks:
    @staticmethod
    def run(args):
        mode = None
        if "respond" in args:
            mode = "respond"; args.remove("respond")
        elif "relay" in args:
            mode = "relay"; args.remove("relay")
        else:
            print(f"{Colors.YELLOW}Select mode:{Colors.RESET}")
            print("  [r] respond (intercept request)")
            print("  [l] relay (intercept response)")
            m = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip().lower()
            if m in ("r", "respond"): mode = "respond"
            elif m in ("l", "relay"): mode = "relay"
            else: print(f"{Colors.RED}Invalid mode, aborting.{Colors.RESET}"); return

        iface = DNSAttacks._extract_iface(args)
        if not iface:
            iface = iface_mgr.get_interface()
            if not iface: print(f"{Colors.RED}No interface given, aborting.{Colors.RESET}"); return
            args.extend(["-i", iface])
        else: iface_mgr._saved_iface = iface

        cmd = ["python3", "-m", DNSFORGE_MODULE] + args + [mode]
        run_command(cmd, "DNS")

    @staticmethod
    def _extract_iface(args):
        for flag in ("-i", "--interface"):
            try: idx = args.index(flag); return args[idx + 1]
            except (ValueError, IndexError): pass
        return None

    @staticmethod
    def quick_menu():
        while True:
            clear_screen(); logo(); banner("Quick DNS Attack Profiles")
            print(f"""{Colors.YELLOW}
  [1] Basic respond (poison all queries)
  [2] Basic relay (poison responses)
  [3] Stealth respond (custom domain + authoritative server)
  [4] Respond with ARP spoofing target
  [5] Respond, no ARP spoofing
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                pip = input(f"{Colors.CYAN}Poison IP: {Colors.RESET}").strip()
                if pip: DNSAttacks.run(["-p", pip])
            elif choice == "2":
                pip = input(f"{Colors.CYAN}Poison IP: {Colors.RESET}").strip()
                if pip: DNSAttacks.run(["-p", pip, "relay"])
            elif choice == "3":
                pip = input(f"{Colors.CYAN}Poison IP: {Colors.RESET}").strip()
                dns_srv = input(f"{Colors.CYAN}Authoritative DNS server IP: {Colors.RESET}").strip()
                domain = input(f"{Colors.CYAN}Victim domain: {Colors.RESET}").strip()
                if pip and dns_srv and domain:
                    DNSAttacks.run(["-p", pip, "-s", "-ds", dns_srv, "-d", domain])
            elif choice == "4":
                pip = input(f"{Colors.CYAN}Poison IP: {Colors.RESET}").strip()
                tgt = input(f"{Colors.CYAN}Target IP for ARP spoofing: {Colors.RESET}").strip()
                if pip and tgt: DNSAttacks.run(["-p", pip, "-t", tgt])
            elif choice == "5":
                pip = input(f"{Colors.CYAN}Poison IP: {Colors.RESET}").strip()
                if pip: DNSAttacks.run(["-p", pip, "--no-arp-spoof"])
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen(); logo(); banner("Advanced DNS Attack Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")
        m = input(f"{Colors.CYAN}Mode: [r] respond / [l] relay: {Colors.RESET}").strip().lower()
        mode = "respond" if m in ("r", "respond") else "relay"
        pip = input(f"{Colors.CYAN}Poison IP (e.g. 192.168.1.100): {Colors.RESET}").strip()
        if not pip: print(f"{Colors.RED}Poison IP is required. Aborting.{Colors.RESET}"); return
        args.extend(["-p", pip])
        qnames = input(f"{Colors.CYAN}DNS query name(s) (comma separated): {Colors.RESET}").strip()
        if qnames: args.extend(["-q", qnames])
        ttl = input(f"{Colors.CYAN}TTL in seconds: {Colors.RESET}").strip()
        if ttl: args.extend(["-ttl", ttl])
        if input(f"{Colors.CYAN}Enable stealth mode? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-s")
            dns_srv = input(f"{Colors.CYAN}  Authoritative DNS server IP: {Colors.RESET}").strip()
            if dns_srv: args.extend(["-ds", dns_srv])
            domain = input(f"{Colors.CYAN}  Victim domain: {Colors.RESET}").strip()
            if domain: args.extend(["-d", domain])
        tgt = input(f"{Colors.CYAN}ARP spoofing target IP (leave empty to skip): {Colors.RESET}").strip()
        if tgt:
            args.extend(["-t", tgt])
        elif input(f"{Colors.CYAN}Use target file instead? [y/N]: {Colors.RESET}").strip().lower() == "y":
            tfile = input(f"{Colors.CYAN}Path to target file: {Colors.RESET}").strip()
            if tfile: args.extend(["-tf", tfile])
        if input(f"{Colors.CYAN}Disable ARP spoofing completely? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("--no-arp-spoof")
        if input(f"{Colors.CYAN}Verbose output? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("-v")
        DHCPAttacks._final_review(args + [mode], lambda a: DNSAttacks.run(a))

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments (including mode): {Colors.RESET}").strip()
        if raw: DNSAttacks.run(raw.split())
        else: print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("DNS Attack Lab (dnsforge)")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw dnsforge arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": DNSAttacks.quick_menu()
            elif choice == "2": DNSAttacks.advanced_wizard()
            elif choice == "3": DNSAttacks.raw_args()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== AD Attacks ====================
class ADAttacks:
    @staticmethod
    def run(args):
        cmd = [str(ADSCAN_SCRIPT)] + args
        run_command(cmd, "Active Directory")

    @staticmethod
    def quick_menu():
        while True:
            clear_screen(); logo(); banner("Quick AD Attack Profiles")
            print(f"""{Colors.YELLOW}
  [1] Kerberoasting (request TGS)
  [2] AS-REP Roasting (users without pre-auth)
  [3] LDAP enumeration (all users)
  [4] BloodHound data collection
  [5] Password spraying (single password)
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                target = input(f"{Colors.CYAN}Domain Controller IP: {Colors.RESET}").strip()
                domain = input(f"{Colors.CYAN}Domain: {Colors.RESET}").strip()
                user = input(f"{Colors.CYAN}Username: {Colors.RESET}").strip()
                password = input(f"{Colors.CYAN}Password: {Colors.RESET}").strip()
                if target and domain and user and password:
                    ADAttacks.run(["kerberoast", "-dc-ip", target, "-d", domain, "-u", user, "-p", password])
            elif choice == "2":
                target = input(f"{Colors.CYAN}Domain Controller IP: {Colors.RESET}").strip()
                domain = input(f"{Colors.CYAN}Domain: {Colors.RESET}").strip()
                if target and domain: ADAttacks.run(["asreproast", "-dc-ip", target, "-d", domain])
            elif choice == "3":
                target = input(f"{Colors.CYAN}Domain Controller IP: {Colors.RESET}").strip()
                domain = input(f"{Colors.CYAN}Domain: {Colors.RESET}").strip()
                user = input(f"{Colors.CYAN}Username: {Colors.RESET}").strip()
                password = input(f"{Colors.CYAN}Password: {Colors.RESET}").strip()
                if target and domain and user and password:
                    ADAttacks.run(["ldap", "-dc-ip", target, "-d", domain, "-u", user, "-p", password, "--users"])
            elif choice == "4":
                target = input(f"{Colors.CYAN}Domain Controller IP: {Colors.RESET}").strip()
                domain = input(f"{Colors.CYAN}Domain: {Colors.RESET}").strip()
                user = input(f"{Colors.CYAN}Username: {Colors.RESET}").strip()
                password = input(f"{Colors.CYAN}Password: {Colors.RESET}").strip()
                if target and domain and user and password:
                    ADAttacks.run(["bloodhound", "-dc-ip", target, "-d", domain, "-u", user, "-p", password])
            elif choice == "5":
                target = input(f"{Colors.CYAN}Domain Controller IP: {Colors.RESET}").strip()
                domain = input(f"{Colors.CYAN}Domain: {Colors.RESET}").strip()
                spray_pass = input(f"{Colors.CYAN}Password to spray: {Colors.RESET}").strip()
                userfile = input(f"{Colors.CYAN}User list file: {Colors.RESET}").strip()
                if target and domain and spray_pass and userfile:
                    ADAttacks.run(["spray", "-dc-ip", target, "-d", domain, "-p", spray_pass, "-U", userfile])
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen(); logo(); banner("Advanced AD Attack Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")
        subcommand = input(f"{Colors.CYAN}Attack type (kerberoast/asreproast/ldap/bloodhound/spray): {Colors.RESET}").strip()
        if subcommand: args.append(subcommand)
        else: print(f"{Colors.RED}Attack type is required.{Colors.RESET}"); return
        target = input(f"{Colors.CYAN}Domain Controller IP (-dc-ip): {Colors.RESET}").strip()
        if target: args.extend(["-dc-ip", target])
        domain = input(f"{Colors.CYAN}Domain (-d): {Colors.RESET}").strip()
        if domain: args.extend(["-d", domain])
        user = input(f"{Colors.CYAN}Username (-u): {Colors.RESET}").strip()
        if user: args.extend(["-u", user])
        password = input(f"{Colors.CYAN}Password (-p): {Colors.RESET}").strip()
        if password: args.extend(["-p", password])
        hashes = input(f"{Colors.CYAN}NTLM hash (optional, overrides password): {Colors.RESET}").strip()
        if hashes: args.extend(["--hashes", hashes])
        user_file = input(f"{Colors.CYAN}User list file (-U): {Colors.RESET}").strip()
        if user_file: args.extend(["-U", user_file])
        if input(f"{Colors.CYAN}Verbose output? [y/N]: {Colors.RESET}").strip().lower() == "y": args.append("-v")
        DHCPAttacks._final_review(args, lambda a: ADAttacks.run(a))

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments (including subcommand): {Colors.RESET}").strip()
        if raw: ADAttacks.run(raw.split())
        else: print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("Active Directory Attack Lab (adscan)")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw adscan arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": ADAttacks.quick_menu()
            elif choice == "2": ADAttacks.advanced_wizard()
            elif choice == "3": ADAttacks.raw_args()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== SMB Attacks ====================
class SMBAttacks:
    @staticmethod
    def run(args):
        cmd = ["python3", str(GHOSTLOCK_SCRIPT)] + args
        run_command(cmd, "SMB Ghostlock")

    @staticmethod
    def quick_menu():
        while True:
            clear_screen(); logo(); banner("Quick SMB Lock Attacks (Ghostlock)")
            print(f"""{Colors.YELLOW}
  [1] Manual UNC path lock (files in folder)
  [2] Auto-discover network shares and lock
  [3] Directory lock (single handle)
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                unc = input(f"{Colors.CYAN}Target UNC path (e.g. \\\\server\\share\\folder): {Colors.RESET}").strip()
                if unc:
                    SMBAttacks.run([unc, "--existing-folder", "--confirm-existing-lock", "--hold-indefinite"])
                else:
                    print(f"{Colors.RED}UNC path required.{Colors.RESET}")
            elif choice == "2":
                print(f"{Colors.YELLOW}Launching interactive auto-discovery...{Colors.RESET}")
                SMBAttacks.run([])
            elif choice == "3":
                unc = input(f"{Colors.CYAN}Target directory UNC path: {Colors.RESET}").strip()
                if unc:
                    SMBAttacks.run([unc, "--existing-folder", "--confirm-existing-lock", "--hold-indefinite", "--dir-lock"])
                else:
                    print(f"{Colors.RED}Directory path required.{Colors.RESET}")
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen(); logo(); banner("Advanced SMB Ghostlock Configuration")
        print(f"{Colors.MUTED}Build your ghostlock command. Leave empty to skip optional flags.{Colors.RESET}\n")
        mode = input(f"{Colors.CYAN}Select locking mode:\n  [1] File-level lock\n  [2] Directory lock\n  [3] Interactive auto-discover\nChoice: {Colors.RESET}").strip()
        if mode == "3":
            print("Launching interactive mode...")
            SMBAttacks.run([])
            return
        unc = input(f"{Colors.CYAN}Target UNC path: {Colors.RESET}").strip()
        if not unc:
            print(f"{Colors.RED}UNC path is required.{Colors.RESET}")
            return
        args.append(unc)
        if input(f"{Colors.CYAN}Confirm existing .ghostlock_authorized file? [Y/n]: {Colors.RESET}").strip().lower() != "n":
            args.append("--confirm-existing-lock")
        if input(f"{Colors.CYAN}Use existing folder safety check? [Y/n]: {Colors.RESET}").strip().lower() != "n":
            args.append("--existing-folder")
        if mode == "1":
            if input(f"{Colors.CYAN}Hold indefinitely? [y/N]: {Colors.RESET}").strip().lower() == "y":
                args.append("--hold-indefinite")
            else:
                secs = input(f"{Colors.CYAN}Hold duration in seconds: {Colors.RESET}").strip()
                if secs: args.extend(["--hold-seconds", secs])
            locks = input(f"{Colors.CYAN}Number of file locks (default many): {Colors.RESET}").strip()
            if locks: args.extend(["--locks", locks])
            victims = input(f"{Colors.CYAN}Number of victim threads: {Colors.RESET}").strip()
            if victims: args.extend(["--victims", victims])
        elif mode == "2":
            args.append("--dir-lock")
            if input(f"{Colors.CYAN}Hold indefinitely? [y/N]: {Colors.RESET}").strip().lower() == "y":
                args.append("--hold-indefinite")
            else:
                secs = input(f"{Colors.CYAN}Hold duration in seconds: {Colors.RESET}").strip()
                if secs: args.extend(["--hold-seconds", secs])
        DHCPAttacks._final_review(args, lambda a: SMBAttacks.run(a))

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw ghostlock arguments: {Colors.RESET}").strip()
        if raw: SMBAttacks.run(raw.split())
        else: print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("SMB Attack Lab (Ghostlock)")
            print(f"""{Colors.YELLOW}
  [1] Quick Lock (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw ghostlock arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": SMBAttacks.quick_menu()
            elif choice == "2": SMBAttacks.advanced_wizard()
            elif choice == "3": SMBAttacks.raw_args()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== Sniffing Lab ====================
class SniffingAttacks:
    @staticmethod
    def run(args):
        cmd = ["python3", str(SNIFFING_SCRIPT)] + args
        run_command(cmd, "Sniffing")

    @staticmethod
    def quick_menu():
        while True:
            clear_screen(); logo(); banner("Quick Sniffing Profiles")
            print(f"""{Colors.YELLOW}
  [1] Capture all packets (Ctrl+C to stop)
  [2] List available interfaces
  [3] Capture HTTP traffic (port 80)
  [4] Capture DNS queries (udp port 53)
  [5] Capture 100 packets
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": SniffingAttacks.run([])
            elif choice == "2": SniffingAttacks.run(["--list-interfaces"])
            elif choice == "3": SniffingAttacks.run(["-f", "tcp port 80"])
            elif choice == "4": SniffingAttacks.run(["-f", "udp port 53"])
            elif choice == "5": SniffingAttacks.run(["-c", "100"])
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen(); logo(); banner("Advanced Sniffing Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")
        iface = input(f"{Colors.CYAN}Interface (e.g. eth0, or leave empty for default): {Colors.RESET}").strip()
        if iface: args.extend(["-i", iface])
        filter_str = input(f"{Colors.CYAN}BPF filter (e.g. 'tcp port 443'): {Colors.RESET}").strip()
        if filter_str: args.extend(["-f", filter_str])
        count = input(f"{Colors.CYAN}Number of packets to capture: {Colors.RESET}").strip()
        if count: args.extend(["-c", count])
        DHCPAttacks._final_review(args, lambda a: SniffingAttacks.run(a))

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments: {Colors.RESET}").strip()
        if raw: SniffingAttacks.run(raw.split())
        else: print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("Sniffing Lab (network_sniffer)")
            print(f"""{Colors.YELLOW}
  [1] Quick Capture (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw sniffer arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": SniffingAttacks.quick_menu()
            elif choice == "2": SniffingAttacks.advanced_wizard()
            elif choice == "3": SniffingAttacks.raw_args()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== DoS Attack Lab ====================
class DOSAttacks:
    @staticmethod
    def run(args):
        cmd = ["python3", "-m", "src"] + args
        run_command(cmd, "DoS", cwd=str(DOS_MODULE_DIR))

    @staticmethod
    def quick_menu():
        while True:
            clear_screen(); logo(); banner("Quick DoS Attack Profiles")
            print(f"""{Colors.YELLOW}
  [1] ARP flood
  [2] SYN flood
  [3] ICMP flood
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice in ("1", "2", "3"):
                target_ip = input(f"{Colors.CYAN}Target IP: {Colors.RESET}").strip()
                if not target_ip:
                    print(f"{Colors.RED}Target IP required.{Colors.RESET}")
                    continue
                if choice == "1": DOSAttacks.run(["--arp", target_ip])
                elif choice == "2": DOSAttacks.run(["--syn", "-i", target_ip])
                elif choice == "3": DOSAttacks.run(["--icmp", "-i", target_ip])
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen(); logo(); banner("Advanced DoS Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")
        attack_type = input(f"{Colors.CYAN}Attack type ([a]rp / [s]yn / [i]cmp): {Colors.RESET}").strip().lower()
        if attack_type in ("a", "arp"): args.append("--arp")
        elif attack_type in ("s", "syn"): args.append("--syn")
        elif attack_type in ("i", "icmp"): args.append("--icmp")
        else: print(f"{Colors.RED}Invalid attack type.{Colors.RESET}"); return

        target_ip = input(f"{Colors.CYAN}Target IP (-i): {Colors.RESET}").strip()
        if target_ip: args.extend(["-i", target_ip])
        source_ip = input(f"{Colors.CYAN}Source IP (-s) (optional): {Colors.RESET}").strip()
        if source_ip: args.extend(["-s", source_ip])
        file_input = input(f"{Colors.CYAN}IP list file (-f) (optional): {Colors.RESET}").strip()
        if file_input: args.extend(["-f", file_input])
        number = input(f"{Colors.CYAN}Number of packets/requests (-n): {Colors.RESET}").strip()
        if number: args.extend(["-n", number])
        threads = input(f"{Colors.CYAN}Threads (--threads): {Colors.RESET}").strip()
        if threads: args.extend(["--threads", threads])
        interface = input(f"{Colors.CYAN}Network interface (--interface): {Colors.RESET}").strip()
        if interface: args.extend(["--interface", interface])

        DHCPAttacks._final_review(args, lambda a: DOSAttacks.run(a))

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments (e.g. --syn -i 192.168.1.10): {Colors.RESET}").strip()
        if raw: DOSAttacks.run(raw.split())
        else: print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("DoS Attack Lab (Net/src)")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw src arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": DOSAttacks.quick_menu()
            elif choice == "2": DOSAttacks.advanced_wizard()
            elif choice == "3": DOSAttacks.raw_args()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== About ====================

ABOUT_ME = """
I`m Erfan Nahidi
Virtualization & Infrastructure Administrator

Focused on designing scalable, resilient, and high-performance datacenter
infrastructures. Passionate about virtualization, Linux systems, networking,
and low-level computing, with a strong interest in systems programming and
infrastructure engineering.
"""

ABOUT_PROJECT = """
This project was developed as part of my Software Project course at
Islamic Azad University, Karaj.

It is provided strictly for educational and research purposes and is intended
to be used only in isolated virtual lab environments.

This software is not designed, tested, or intended for use against production
systems or unauthorized targets. The author assumes no responsibility for any
misuse or damages resulting from the use of this project.
"""

class About:
    @staticmethod
    def Me():
        clear_screen()
        logo()
        banner("About Me")
        print(f"{Colors.CYAN}{ABOUT_ME.strip()}{Colors.RESET}")
        pause()

    @staticmethod
    def Project():
        clear_screen()
        logo()
        banner("About This Project")
        print(f"{Colors.YELLOW}{ABOUT_PROJECT.strip()}{Colors.RESET}")
        pause()

    @staticmethod
    def main_menu():
        while True:
            clear_screen(); logo(); banner("About Menu")
            print(f"""{Colors.YELLOW}
  [1] About Me
  [2] About this Project
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": About.Me()
            elif choice == "2": About.Project()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

# ==================== Main Dashboard ====================
def main_menu():
    while True:
        clear_screen(); logo(); banner("Security Learning Dashboard")
        print(f"""{Colors.YELLOW}
  [1] DHCP Attack Lab
  [2] DNS Attack Lab
  [3] Active Directory Attack Lab
  [4] SMB Attack Lab
  [5] Sniffing Lab
  [6] DoS Attack Lab
  [7] About
  [0] Exit
{Colors.RESET}""")
        choice = input(f"{Colors.CYAN}Select a module: {Colors.RESET}").strip()
        if choice == "1": DHCPAttacks.main_menu()
        elif choice == "2": DNSAttacks.main_menu()
        elif choice == "3": ADAttacks.main_menu()
        elif choice == "4": SMBAttacks.main_menu()
        elif choice == "5": SniffingAttacks.main_menu()
        elif choice == "6": DOSAttacks.main_menu()
        elif choice == "7": About.main_menu()
        elif choice in ("0", "q", "Q", "exit"):
            clear_screen()
            print(f"{Colors.MUTED}Stay curious. Stay authorized.{Colors.RESET}")
            break
        else:
            print(f"{Colors.RED}Please select a listed option.{Colors.RESET}")

def handle_arg(arg):
    arg = arg.lower()
    if arg in ("dhcplab", "dhcp", "7"): DHCPAttacks.main_menu()
    elif arg in ("dnsattack", "dns", "8"): DNSAttacks.main_menu()
    elif arg in ("adattack", "ad", "9"): ADAttacks.main_menu()
    elif arg in ("smbattack", "smb", "ghostlock", "10"): SMBAttacks.main_menu()
    elif arg in ("sniffing", "sniff", "11"): SniffingAttacks.main_menu()
    elif arg in ("dos", "dosattack", "12"): DOSAttacks.main_menu()
    elif arg in ("-h", "--help"):
        print(f"""Project Nemesis v{VERSION}
Usage: {sys.argv[0]} [module]
Modules:
  dhcplab / dhcp       DHCP Attack Lab
  dnsattack / dns      DNS Attack Lab
  adattack / ad        Active Directory Attack Lab
  smbattack / smb      SMB Ghostlock Attack Lab
  sniffing / sniff     Sniffing Lab
  dos / dosattack      DoS Attack Lab
  about                About Menu
  -h, --help           Show this help
  --version            Show version
  --check              Verify all tools
""")
    elif arg == "--version":
        print(f"Project Nemesis v{VERSION}")
    elif arg == "--check":
        print(f"{Colors.GREEN}✓ All tools verified successfully.{Colors.RESET}")
    elif arg == "about":
        About.main_menu()
    else:
        print(f"{Colors.RED}Unknown module: {arg}{Colors.RESET}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        handle_arg(sys.argv[1])
    else:
        main_menu()