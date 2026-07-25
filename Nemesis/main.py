#!/usr/bin/env python3
"""
Project Nemesis — a safe, educational network‑security dashboard.
Created for the software project course at Karaj Azad University.

Usage:
    nemesis.py [module]
    nemesis.py --help
    nemesis.py --version

Run with root privileges for attack modules to work.
"""

import argparse
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

VERSION = "1.4.3"
LOG_FILE = Path.home() / ".nemesis.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

SCRIPT_DIR = Path(__file__).resolve().parent

# Tool locations – use the exact folder names from your project
SCANNER_CORE = SCRIPT_DIR / "scanner" / "core.py"
SCANNER_CLI  = SCRIPT_DIR / "scanner" / "cli.py"
PIG_SCRIPT = SCRIPT_DIR / "DHCP" / "pig.py"
DNSFORGE_DIR = SCRIPT_DIR / "DNS"
ADSCAN_SCRIPT = SCRIPT_DIR / "AD" / "adscan.py"
GHOSTLOCK_SCRIPT = SCRIPT_DIR / "SMB" / "ghostlock.py"
SNIFFING_SCRIPT = SCRIPT_DIR / "sniffing" / "network_sniffer.py"


# ----------------------------------------------------------------------
# Validation helpers
# ----------------------------------------------------------------------
def verify_tools():
    """Check that all required files and directories exist. Raise on failure."""
    required = {
        "scanner/core.py": SCANNER_CORE,
        "scanner/cli.py":  SCANNER_CLI,
        "pig.py":          PIG_SCRIPT,
        "adscan.py":       ADSCAN_SCRIPT,
        "ghostlock.py":    GHOSTLOCK_SCRIPT,
        "network_sniffer.py": SNIFFING_SCRIPT,
        "DNS/ package":    DNSFORGE_DIR / "__init__.py",
    }
    missing = [name for name, path in required.items() if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "The following required components are missing:\n  "
            + "\n  ".join(missing)
            + f"\nExpected in {SCRIPT_DIR}"
        )


def check_interface_exists(iface):
    """Verify that a network interface exists (Linux only)."""
    try:
        subprocess.run(
            ["ip", "link", "show", iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False



# ----------------------------------------------------------------------
# Terminal colour support (stripped if stdout is not a tty)
# ----------------------------------------------------------------------
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
    top = f"{Colors.RED}{Colors.TOPL}{Colors.HLINE * (width - 2)}{Colors.TOPR}"
    pad = (width - 2 - len(text)) // 2
    middle = (
        f"{Colors.VLINE}{' ' * pad}{Colors.BOLD}{text}{Colors.RESET}{Colors.RED}"
        f"{' ' * (width - 2 - len(text) - pad)}{Colors.VLINE}"
    )
    bottom = f"{Colors.BOTL}{Colors.HLINE * (width - 2)}{Colors.BOTR}{Colors.RESET}"
    print(top)
    print(middle)
    print(bottom)


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


def confirm_attack(desc):
    print(f"\n{Colors.RED}You are about to run:{Colors.RESET}")
    print(f"  {Colors.BOLD}{desc}{Colors.RESET}")
    print(f"{Colors.RED}This requires root and must ONLY be done on authorised networks.{Colors.RESET}")
    answer = input(f"{Colors.CYAN}Type 'yes' to confirm: {Colors.RESET}").strip().lower()
    return answer in ("y", "yes", "yep", "yeah")


# ----------------------------------------------------------------------
# Sensitive argument redaction (prevents password leaks in logs)
# ----------------------------------------------------------------------
SENSITIVE_FLAGS = {
    "-p", "--password",
    "--hashes",
}

def redact_sensitive_args(cmd_list):
    """
    Return a new list with values of sensitive flags replaced by '***'.
    Works on typical `-p password` or `--password pass` patterns.
    """
    redacted = []
    skip_next = False
    for i, token in enumerate(cmd_list):
        if skip_next:
            redacted.append("***")
            skip_next = False
            continue
        if token in SENSITIVE_FLAGS:
            redacted.append(token)
            # Next token is the value
            if i + 1 < len(cmd_list) and not cmd_list[i + 1].startswith("-"):
                skip_next = True
            else:
                pass
        else:
            redacted.append(token)
    return redacted


# ----------------------------------------------------------------------
# Interface manager (remembers the last chosen NIC)
# ----------------------------------------------------------------------
class InterfaceManager:
    def __init__(self):
        self._saved = None

    def get_interface(self):
        if self._saved:
            use = input(
                f"{Colors.CYAN}Use saved interface {Colors.BOLD}{self._saved}"
                f"{Colors.RESET}{Colors.CYAN}? [Y/n]: {Colors.RESET}"
            ).strip().lower()
            if use not in ("n", "no"):
                return self._saved
        while True:
            iface = input(f"{Colors.CYAN}Network interface (e.g. eth0, vboxnet0): {Colors.RESET}").strip()
            if not iface:
                return None
            if check_interface_exists(iface):
                self._saved = iface
                return iface
            else:
                print(f"{Colors.RED}Interface '{iface}' not found. Please try again.{Colors.RESET}")

    def set_interface(self, iface):
        if iface and check_interface_exists(iface):
            self._saved = iface
        elif iface:
            print(f"{Colors.YELLOW}Warning: interface '{iface}' not found, but will be used anyway.{Colors.RESET}")
            self._saved = iface


iface_mgr = InterfaceManager()


# ----------------------------------------------------------------------
# Attack execution core (logs and runs commands)
# ----------------------------------------------------------------------
def run_attack(cmd, attack_type, cwd=None):
    """Confirm, log, and execute an attack command."""
    log_cmd = redact_sensitive_args(cmd)
    desc = " ".join(log_cmd)

    clear_screen()
    logo()
    banner(f"Execute {attack_type} Attack")
    print(f"\n{Colors.YELLOW}Command:{Colors.RESET}\n  {desc}")
    print(f"{Colors.GREEN}{'━' * 50}{Colors.RESET}")

    if not confirm_attack(desc):
        print(f"{Colors.MUTED}Attack cancelled.{Colors.RESET}")
        pause()
        return

    logging.info(f"ATTACK [{attack_type}]: {desc}")

    print(f"\n{Colors.CYAN}Launching attack...{Colors.RESET}")
    print(f"{Colors.MUTED}(Press Ctrl+C to stop){Colors.RESET}\n")

    try:
        if os.geteuid() != 0:
            result = subprocess.run(["sudo"] + cmd, cwd=cwd or str(SCRIPT_DIR), capture_output=False)
        else:
            result = subprocess.run(cmd, cwd=cwd or str(SCRIPT_DIR), capture_output=False)
    except KeyboardInterrupt:
        print(f"\n{Colors.MUTED}Attack interrupted by user.{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Error: {e}{Colors.RESET}")
    else:
        if result.returncode != 0:
            print(f"{Colors.RED}Command exited with non‑zero status ({result.returncode}).{Colors.RESET}")
            if hasattr(result, "stderr") and result.stderr:
                print(f"{Colors.MUTED}{result.stderr}{Colors.RESET}")
        else:
            print(f"\n{Colors.GREEN}Attack finished successfully.{Colors.RESET}")
    pause()


# ----------------------------------------------------------------------
# Base class for attack modules (reduces duplication)
# ----------------------------------------------------------------------
class AttackModule:
    """Provides common menu logic and argument‑extraction helpers."""

    @staticmethod
    def _extract_iface(args, flags=("-i", "--interface")):
        for flag in flags:
            try:
                idx = args.index(flag)
                return args[idx + 1]
            except (ValueError, IndexError):
                pass
        return None

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
    def raw_args(run_func, arg_name="arguments"):
        raw = input(f"{Colors.CYAN}Enter raw {arg_name}: {Colors.RESET}").strip()
        if raw:
            run_func(raw.split())
        else:
            print(f"{Colors.RED}No {arg_name} given.{Colors.RESET}")


# ----------------------------------------------------------------------
# Scanner wrapper (imports the scanner menu from scanner/cli.py)
# ----------------------------------------------------------------------
class Scanner:
    @staticmethod
    def main_menu():
        clear_screen()
        logo()
        banner("Scanner Module")
        try:
            # Import the scanner's interactive menu
            from scanner.cli import ScannerMenu
            # Run it – the menu handles its own loop and screen clearing
            ScannerMenu.main_menu()
        except ImportError as e:
            print(f"{Colors.RED}Failed to import scanner module: {e}{Colors.RESET}")
            print(f"{Colors.YELLOW}Make sure 'scanner/cli.py' and 'scanner/core.py' exist.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Scanner error: {e}{Colors.RESET}")
        pause()


# ----------------------------------------------------------------------
# DHCP Attacks
# ----------------------------------------------------------------------
class DHCPAttacks(AttackModule):
    @staticmethod
    def run(args):
        iface = DHCPAttacks._extract_iface(args, flags=("-i",))
        if not iface:
            iface = iface_mgr.get_interface()
            if not iface:
                print(f"{Colors.RED}No interface given, aborting.{Colors.RESET}")
                return
            args.extend(["-i", iface])
        else:
            iface_mgr.set_interface(iface)
        cmd = [str(PIG_SCRIPT)] + args
        run_attack(cmd, "DHCP")

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
        for opt, flag in [
            ("Show ARP who-has?", "-a"),
            ("Show ICMP requests?", "-i"),
            ("Show lease options?", "-o"),
            ("Show lease confirmations?", "-l"),
            ("Gratuitous ARP neighbor attack?", "-g"),
            ("Release all neighbor IPs?", "-r"),
            ("ARP neighbor scan?", "-n"),
        ]:
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
            if choice == "1": DHCPAttacks.quick_menu()
            elif choice == "2": DHCPAttacks.advanced_wizard()
            elif choice == "3": AttackModule.raw_args(DHCPAttacks.run, "pig.py arguments")
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")


# ----------------------------------------------------------------------
# DNS Attacks (dnsforge)
# ----------------------------------------------------------------------
class DNSAttacks(AttackModule):
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
            iface_mgr.set_interface(iface)

        cmd = ["python3", "-m", "DNS"] + args + [mode]
        run_attack(cmd, "DNS")

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
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")

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
        DNSAttacks._final_review(args + [mode], lambda a: DNSAttacks.run(a))

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
            if choice == "1": DNSAttacks.quick_menu()
            elif choice == "2": DNSAttacks.advanced_wizard()
            elif choice == "3": AttackModule.raw_args(DNSAttacks.run, "dnsforge arguments")
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")


# ----------------------------------------------------------------------
# Active Directory Attacks
# ----------------------------------------------------------------------
class ADAttacks(AttackModule):
    @staticmethod
    def run(args):
        cmd = [str(ADSCAN_SCRIPT)] + args
        run_attack(cmd, "Active Directory")

    @staticmethod
    def quick_menu():
        while True:
            clear_screen()
            logo()
            banner("Quick AD Attack Profiles")
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
        clear_screen()
        logo()
        banner("Advanced AD Attack Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")
        subcmd = input(f"{Colors.CYAN}Attack type (kerberoast/asreproast/ldap/bloodhound/spray): {Colors.RESET}").strip()
        if subcmd:
            args.append(subcmd)
        else:
            print(f"{Colors.RED}Attack type is required.{Colors.RESET}")
            return
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
        if input(f"{Colors.CYAN}Verbose output? [y/N]: {Colors.RESET}").strip().lower() == "y":
            args.append("-v")
        ADAttacks._final_review(args, lambda a: ADAttacks.run(a))

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("Active Directory Attack Lab (adscan)")
            print(f"""{Colors.YELLOW}
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw adscan arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": ADAttacks.quick_menu()
            elif choice == "2": ADAttacks.advanced_wizard()
            elif choice == "3": AttackModule.raw_args(ADAttacks.run, "adscan arguments")
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")


# ----------------------------------------------------------------------
# SMB Ghostlock Attacks
# ----------------------------------------------------------------------
class SMBAttacks(AttackModule):
    @staticmethod
    def run(args):
        cmd = ["python3", str(GHOSTLOCK_SCRIPT)] + args
        run_attack(cmd, "SMB Ghostlock")

    @staticmethod
    def quick_menu():
        while True:
            clear_screen()
            logo()
            banner("Quick SMB Lock Attacks (Ghostlock)")
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
        clear_screen()
        logo()
        banner("Advanced SMB Ghostlock Configuration")
        print(f"{Colors.MUTED}Build your ghostlock command. Leave empty to skip optional flags.{Colors.RESET}\n")
        mode = input(
            f"{Colors.CYAN}Select locking mode:\n  [1] File-level lock\n  [2] Directory lock\n  [3] Interactive auto-discover\nChoice: {Colors.RESET}"
        ).strip()
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
        SMBAttacks._final_review(args, lambda a: SMBAttacks.run(a))

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("SMB Attack Lab (Ghostlock)")
            print(f"""{Colors.YELLOW}
  [1] Quick Lock (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw ghostlock arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": SMBAttacks.quick_menu()
            elif choice == "2": SMBAttacks.advanced_wizard()
            elif choice == "3": AttackModule.raw_args(SMBAttacks.run, "ghostlock arguments")
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")


# ----------------------------------------------------------------------
# Sniffing Lab
# ----------------------------------------------------------------------
class SniffingAttacks(AttackModule):
    @staticmethod
    def run(args):
        cmd = ["python3", str(SNIFFING_SCRIPT)] + args
        run_attack(cmd, "Sniffing")

    @staticmethod
    def quick_menu():
        while True:
            clear_screen()
            logo()
            banner("Quick Sniffing Profiles")
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
        clear_screen()
        logo()
        banner("Advanced Sniffing Configuration")
        print(f"{Colors.MUTED}Configure each option. Leave empty to skip.{Colors.RESET}\n")
        iface = input(f"{Colors.CYAN}Interface (e.g. eth0, or leave empty for default): {Colors.RESET}").strip()
        if iface: args.extend(["-i", iface])
        filter_str = input(f"{Colors.CYAN}BPF filter (e.g. 'tcp port 443'): {Colors.RESET}").strip()
        if filter_str: args.extend(["-f", filter_str])
        count = input(f"{Colors.CYAN}Number of packets to capture: {Colors.RESET}").strip()
        if count: args.extend(["-c", count])
        SniffingAttacks._final_review(args, lambda a: SniffingAttacks.run(a))

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("Sniffing Lab (network_sniffer)")
            print(f"""{Colors.YELLOW}
  [1] Quick Capture (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw sniffer arguments
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": SniffingAttacks.quick_menu()
            elif choice == "2": SniffingAttacks.advanced_wizard()
            elif choice == "3": AttackModule.raw_args(SniffingAttacks.run, "sniffer arguments")
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")


# ----------------------------------------------------------------------
# About / Update menus
# ----------------------------------------------------------------------
ABOUT_ME = """
I'm Erfan Nahidi
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
    def about_me():
        clear_screen()
        logo()
        banner("About Me")
        print(f"{Colors.CYAN}{ABOUT_ME.strip()}{Colors.RESET}")
        pause()

    @staticmethod
    def about_project():
        clear_screen()
        logo()
        banner("About This Project")
        print(f"{Colors.YELLOW}{ABOUT_PROJECT.strip()}{Colors.RESET}")
        pause()

    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("About Menu")
            print(f"""{Colors.YELLOW}
  [1] About Me
  [2] About this Project
  [0] Return to main menu
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": About.about_me()
            elif choice == "2": About.about_project()
            elif choice == "0": break
            else: print(f"{Colors.RED}Invalid option.{Colors.RESET}")


class Update:
    @staticmethod
    def main_menu():
        while True:
            clear_screen()
            logo()
            banner("Update & Maintenance")
            print(f"""{Colors.YELLOW}
  [1] Install / update requirements (pip)
  [2] Pull latest project from GitHub
  [0] Back
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Choice: {Colors.RESET}").strip()
            if choice == "1": Update.install_requirements()
            elif choice == "2": Update.update_project()
            elif choice == "0": break
            else:
                print(f"{Colors.RED}Invalid option.{Colors.RESET}")
                pause()

    @staticmethod
    def install_requirements():
        clear_screen()
        logo()
        banner("Install Requirements")
        req_file = SCRIPT_DIR / "requirements.txt"
        if not req_file.exists():
            print(f"{Colors.YELLOW}No requirements.txt found at {req_file}.{Colors.RESET}")
            print("Create one or install packages manually.")
            pause()
            return

        print(f"{Colors.RED}WARNING: Installing packages from the internet can be risky.{Colors.RESET}")
        print(f"{Colors.RED}Make sure you trust the source of '{req_file}'.{Colors.RESET}")
        ans = input(f"{Colors.CYAN}Type 'yes' to proceed: {Colors.RESET}").strip().lower()
        if ans not in ("y", "yes"):
            print(f"{Colors.MUTED}Installation cancelled.{Colors.RESET}")
            pause()
            return

        print(f"{Colors.CYAN}Installing from {req_file}...{Colors.RESET}")
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-r", str(req_file)], check=True)
            print(f"{Colors.GREEN}Installation complete.{Colors.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error during installation: {e}{Colors.RESET}")
        pause()

    @staticmethod
    def update_project():
        clear_screen()
        logo()
        banner("Update Project from Git")
        git_dir = SCRIPT_DIR / ".git"
        if not git_dir.exists():
            print(f"{Colors.YELLOW}Not a git repository. Cannot update.{Colors.RESET}")
            pause()
            return

        print(f"{Colors.RED}WARNING: Pulling code from remote repository may introduce untrusted changes.{Colors.RESET}")
        ans = input(f"{Colors.CYAN}Type 'yes' to proceed: {Colors.RESET}").strip().lower()
        if ans not in ("y", "yes"):
            print(f"{Colors.MUTED}Update cancelled.{Colors.RESET}")
            pause()
            return

        print(f"{Colors.CYAN}Running git pull...{Colors.RESET}")
        try:
            result = subprocess.run(["git", "pull"], cwd=str(SCRIPT_DIR), capture_output=True, text=True)
            if result.returncode == 0:
                print(f"{Colors.GREEN}Update successful.{Colors.RESET}")
                print(result.stdout)
            else:
                print(f"{Colors.RED}Update failed:{Colors.RESET}")
                print(result.stderr)
        except Exception as e:
            print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        pause()


# ----------------------------------------------------------------------
# Main Dashboard & CLI entry point
# ----------------------------------------------------------------------
MODULE_MAP = {
    "1": Scanner.main_menu,
    "scanner": Scanner.main_menu,
    "2": DHCPAttacks.main_menu,
    "dhcp": DHCPAttacks.main_menu,
    "dhcplab": DHCPAttacks.main_menu,
    "3": DNSAttacks.main_menu,
    "dns": DNSAttacks.main_menu,
    "dnsattack": DNSAttacks.main_menu,
    "4": ADAttacks.main_menu,
    "ad": ADAttacks.main_menu,
    "adattack": ADAttacks.main_menu,
    "5": SMBAttacks.main_menu,
    "smb": SMBAttacks.main_menu,
    "smbattack": SMBAttacks.main_menu,
    "ghostlock": SMBAttacks.main_menu,
    "6": SniffingAttacks.main_menu,
    "sniffing": SniffingAttacks.main_menu,
    "sniff": SniffingAttacks.main_menu,
    "7": Update.main_menu,
    "update": Update.main_menu,
    "8": About.main_menu,
    "about": About.main_menu,
}


def main():
    parser = argparse.ArgumentParser(
        description=f"Project Nemesis v{VERSION} – network security learning dashboard.",
        usage="nemesis.py [module] [--help] [--version] [--check]",
    )
    parser.add_argument("module", nargs="?", help="Module name or number to launch directly")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    parser.add_argument("--check", action="store_true", help="Verify all tools and exit")
    args = parser.parse_args()

    if args.version:
        print(f"Project Nemesis v{VERSION}")
        return
    if args.check:
        try:
            verify_tools()
            print(f"{Colors.GREEN}✓ All tools verified successfully.{Colors.RESET}")
        except FileNotFoundError as e:
            print(f"{Colors.RED}✗ {e}{Colors.RESET}")
        return

    try:
        verify_tools()
    except FileNotFoundError as e:
        sys.exit(f"{Colors.RED}ERROR: {e}{Colors.RESET}")

    if args.module:
        module = args.module.lower()
        if module in MODULE_MAP:
            MODULE_MAP[module]()
        else:
            print(f"{Colors.RED}Unknown module: {module}{Colors.RESET}", file=sys.stderr)
            sys.exit(1)
    else:
        # Interactive dashboard loop
        while True:
            clear_screen()
            logo()
            banner("Security Learning Dashboard")
            print(f"""{Colors.YELLOW}
  [1] Service Scanner
  [2] DHCP Attacker
  [3] DNS Attacker
  [4] Active Directory Attacker
  [5] SMB Attacker
  [6] Sniffing
  [7] Update & Maintenance
  [8] About
  [0] Exit
{Colors.RESET}""")
            choice = input(f"{Colors.CYAN}Select a module: {Colors.RESET}").strip()
            if choice in ("0", "q", "Q", "exit"):
                clear_screen()
                print(f"{Colors.MUTED}Stay curious. Stay authorized.{Colors.RESET}")
                break
            elif choice in MODULE_MAP:
                MODULE_MAP[choice]()
            else:
                print(f"{Colors.RED}Please select a listed option.{Colors.RESET}")


if __name__ == "__main__":
    main()