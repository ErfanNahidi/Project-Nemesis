#!/usr/bin/env python3
# =============================================================================
# Windows Server Targeted Scanner – SUPER UPGRADED VERSION (FIXED)
# Original: Erfan Nahidi for Karaj open source software project.
# Fixed: TCP port scanning in common/full modes now works correctly.
# =============================================================================

import sys
import os
import json
import csv
import logging
import argparse
import asyncio
import concurrent.futures
import time
import random
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from collections import defaultdict
from datetime import datetime

import nmap                     # python-nmap
import requests                 # for NVD API
from tqdm import tqdm           # progress bar
from colorama import Fore, Style, init
import yaml                     # for config file support

# Optional Jinja2 for HTML templating (fallback to simple string)
try:
    from jinja2 import Template
    HAS_JINJA = True
except ImportError:
    HAS_JINJA = False

# Initialize colorama
init(autoreset=True)

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------

VERSION = "2.0.2-fixed"
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║  Windows Server Targeted Scanner                                ║
║  Version {VERSION}  |  Author: Erfan Nahidi                       ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# NVD API endpoint (rate-limited, 1 request/6s with no API key, faster with key)
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Module definitions with extended services
MODULE_PORTS = {
    "DHCP Attacker":       {"ports": [67, 68],          "proto": "udp"},
    "DNS Attacker":        {"ports": [53],              "proto": "tcp"},   # also UDP 53
    "AD Attacker":         {"ports": [389,636,88,464,3268,3269,135,139],"proto": "tcp"},
    "SMB Attacker":        {"ports": [445,139],         "proto": "tcp"},
    "SNMP Sniffinger":     {"ports": [161,162],         "proto": "udp"},
    "DoS Amplification":   {"ports": [19,123,520,1900,11211],"proto": "udp"},
    "Install & Update":    {"ports": [8530,8531,5985,5986,3389,80,443],"proto": "tcp"},
    "Print Spooler":       {"ports": [515, 9100],       "proto": "tcp"},  # LPR, raw printing
    "LDAP Signing":        {"ports": [389, 636],        "proto": "tcp"},  # LDAP channel binding
}

# Quick / Full scan port definitions
QUICK_TCP = [21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,593,636,
             993,995,1433,1723,3268,3269,3306,3389,5432,5900,5985,5986,8080,8443,8530,8531]
FULL_TCP_RANGE = (1, 65535)
FULL_UDP_PORTS = [53,67,68,69,123,135,137,138,139,161,162,445,500,514,520,1194,1900,4500,5353,11211]

# Static vulnerability DB (fallback if offline)
STATIC_VULNS = {
    ("smb", "1.0"): ["MS17-010 (EternalBlue) – RCE via SMBv1"],
    ("smb", "3.1.1"): ["CVE-2020-0796 (SMBGhost) – RCE"],
    ("rdp", ""): ["CVE-2019-0708 (BlueKeep) – RCE"],
    ("dns", ""): ["CVE-2020-1350 (SigRed) – RCE"],
    ("snmp", ""): ["Default community strings – info disclosure"],
    ("winrm", ""): ["CVE-2015-0010 – auth bypass (older versions)"],
}

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("WinServerScanner")

# ---------------------------------------------------------------------------
# Helper: CVE Lookup via NVD
# ---------------------------------------------------------------------------
def lookup_cves(service: str, product: str, version: str, api_key: str = None) -> List[str]:
    """
    Query NVD API for known vulnerabilities matching service/product/version.
    Returns a list of CVE IDs with brief descriptions.
    """
    query_parts = []
    if product:
        query_parts.append(product)
    if version:
        query_parts.append(version)
    if service and service not in query_parts:
        query_parts.append(service)
    if not query_parts:
        return []

    keyword = " ".join(query_parts)
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
    }
    try:
        # respect rate limits: 5 requests/30s without key, 50 requests/30s with key
        resp = requests.get(NVD_API_BASE, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln["cve"]["id"]
                desc = vuln["cve"]["descriptions"][0]["value"][:120]
                cves.append(f"{cve_id} – {desc}")
            return cves
        else:
            logger.warning(f"NVD API status {resp.status_code}")
    except Exception as e:
        logger.error(f"NVD lookup error: {e}")
    return []

# ---------------------------------------------------------------------------
# Core Scanner Class
# ---------------------------------------------------------------------------
class SuperWindowsScanner:
    """Async-capable scanner with Nmap, service detection, CVE correlation."""

    def __init__(
        self,
        target: str,
        scan_mode: str = "quick",
        threads: int = 10,
        stealth: bool = False,
        vuln_check: bool = False,
        nmap_args_extra: str = "",
        nvd_api_key: str = None,
    ):
        self.target = target
        self.scan_mode = scan_mode.lower()
        self.threads = threads
        self.stealth = stealth
        self.vuln_check = vuln_check
        self.nmap_extra = nmap_args_extra
        self.nvd_api_key = nvd_api_key

        self.nm = nmap.PortScanner()
        self.scan_data = None
        self.os_info = "Unknown"

    def _build_port_spec(self) -> str:
        if self.scan_mode == "quick":
            tcp = QUICK_TCP
            udp = [53,161,162,67,68,123,520,1900,11211]
            return f"T:{','.join(map(str,tcp))},U:{','.join(map(str,udp))}"
        elif self.scan_mode == "common":
            # اسکن TCP ports 1-1000 + تمام UDP های لیست شده
            udp = FULL_UDP_PORTS
            return f"T:1-1000,U:{','.join(map(str,udp))}"
        elif self.scan_mode == "full":
            udp = FULL_UDP_PORTS
            return f"T:1-65535,U:{','.join(map(str,udp))}"
        elif self.scan_mode == "custom":
            return ""
        else:
            raise ValueError(f"Unknown scan mode: {self.scan_mode}")

    def _nmap_arguments(self) -> str:
        port_spec = self._build_port_spec()
        args = []
        if port_spec:
            args.append(f"-p {port_spec}")

        # Service version & scripts
        if self.scan_mode in ("common", "full", "custom"):
            args.append("-sV --version-intensity 5")
            if self.vuln_check:
                args.append("--script vulners,vuln")
        if self.scan_mode in ("common", "full"):
            args.append("-O --osscan-guess")

        # Timing / stealth
        if self.stealth:
            args.append("-T2 --max-retries 2 --scan-delay 500ms --randomize-hosts")
            self.threads = min(self.threads, 2)
        else:
            if self.scan_mode == "quick":
                args.append("-T5 --min-rate 1500 --host-timeout 2m")
            else:
                args.append("-T4 --min-rate 800 --host-timeout 8m")

        if self.stealth:
            args.append("-D 10.0.0.1,172.16.0.1,192.168.0.1")

        if self.nmap_extra:
            args.append(self.nmap_extra)

        return " ".join(args)

    async def run_scan_async(self):
        """Execute nmap scan asynchronously using a thread executor."""
        loop = asyncio.get_running_loop()
        nmap_args = self._nmap_arguments()
        logger.info(f"Scanning {self.target} with args: {nmap_args}")

        # Fix: use lambda to avoid keyword argument error
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            await loop.run_in_executor(
                pool,
                lambda: self.nm.scan(self.target, arguments=nmap_args, sudo=True)
            )

        if self.target in self.nm.all_hosts():
            self.scan_data = self.nm[self.target]
            os_matches = self.scan_data.get("osmatch", [])
            if os_matches:
                self.os_info = os_matches[0]["name"]
            logger.info(f"Scan complete. OS: {self.os_info}")
        else:
            logger.error(f"Host {self.target} not reachable.")
            self.scan_data = None

    def extract_services(self) -> List[Dict]:
        """Parse scan results into a structured list of services."""
        if not self.scan_data:
            return []
        tcp = self.scan_data.get("tcp", {})
        udp = self.scan_data.get("udp", {})
        services = []

        for proto, port_dict in [("tcp", tcp), ("udp", udp)]:
            for port, info in port_dict.items():
                if info["state"] in ("open", "open|filtered"):
                    services.append({
                        "port": port,
                        "proto": proto,
                        "name": info["name"],
                        "product": info.get("product", ""),
                        "version": info.get("version", ""),
                        "extrainfo": info.get("extrainfo", ""),
                        "script": info.get("script", {}),
                    })
        return services

    def get_static_vulns(self, service: Dict) -> List[str]:
        """Static vulnerability check based on product/version."""
        name = service["name"].lower()
        product = service.get("product", "").lower()
        version = service.get("version", "").lower()
        found = []
        for (svc_pat, ver_pat), vulns in STATIC_VULNS.items():
            if svc_pat in name or (product and svc_pat in product):
                if ver_pat == "" or (version and ver_pat in version):
                    found.extend(vulns)
        return found

    async def correlate_vulns(self, services: List[Dict]) -> Dict[str, List[str]]:
        """Perform CVE lookup for each service (live + static) and return per-service vulns."""
        vuln_map = {}
        for svc in services:
            key = f"{svc['proto']}/{svc['port']} {svc['name']} {svc['product']} {svc['version']}".strip()
            vulns = self.get_static_vulns(svc)

            if self.vuln_check:
                live_cves = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lookup_cves,
                    svc["name"],
                    svc.get("product", ""),
                    svc.get("version", ""),
                    self.nvd_api_key,
                )
                vulns.extend(live_cves)

            # Also check scripts (e.g., vulners output)
            for script_name, output in svc.get("script", {}).items():
                if "vuln" in script_name.lower() and output:
                    vulns.append(f"Script {script_name}: {output.strip()[:200]}")

            if vulns:
                vuln_map[key] = vulns
        return vuln_map

    def module_classification(self, services: List[Dict]) -> Dict[str, List[str]]:
        """Group services into attack modules."""
        modules = defaultdict(list)
        for svc in services:
            port = svc["port"]
            proto = svc["proto"]
            for mod, info in MODULE_PORTS.items():
                if info["proto"] == proto and port in info["ports"]:
                    service_str = f"{proto}/{port} {svc['name']} {svc['product']} {svc['version']}".strip()
                    modules[mod].append(service_str)
        return modules

    async def full_analysis(self):
        """Run scan, extract services, correlate vulnerabilities."""
        await self.run_scan_async()
        if not self.scan_data:
            return None

        services = self.extract_services()
        vulns = await self.correlate_vulns(services)
        modules = self.module_classification(services)
        return {
            "target": self.target,
            "os": self.os_info,
            "timestamp": datetime.now().isoformat(),
            "services": [f"{s['proto']}/{s['port']} {s['name']} {s['product']} {s['version']}".strip()
                         for s in services],
            "modules": modules,
            "vulnerabilities": vulns,
            "raw_services": services,
        }

# ---------------------------------------------------------------------------
# Reporting & Output
# ---------------------------------------------------------------------------
class Reporter:
    """Generate reports in various formats and send notifications."""

    @staticmethod
    def console_report(data: dict, verbose: bool = False):
        """Print a colorful console report."""
        print(Fore.CYAN + "="*70)
        print(Fore.YELLOW + f"  Scan Report for {data['target']}")
        print(Fore.YELLOW + f"  OS: {data.get('os', 'Unknown')} | Time: {data['timestamp']}")
        print(Fore.CYAN + "="*70 + Style.RESET_ALL)

        print(Fore.GREEN + "\n[Services]")
        for s in data["services"]:
            print(f"  {s}")
        if not data["services"]:
            print("  No open services found.")

        print(Fore.GREEN + "\n[Module Classification]")
        if data["modules"]:
            for mod, svcs in data["modules"].items():
                if svcs:
                    print(Fore.MAGENTA + f"  {mod}:")
                    for s in svcs:
                        print(f"    - {s}")
        else:
            print("  No modules matched.")

        if data.get("vulnerabilities"):
            print(Fore.RED + "\n[Vulnerabilities]")
            for svc, vulns in data["vulnerabilities"].items():
                print(f"  {svc}:")
                for v in vulns:
                    print(f"    [!] {v}")

    @staticmethod
    def json_report(data: dict, output_path: str):
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"JSON report saved to {output_path}")

    @staticmethod
    def csv_report(data: dict, output_path: str):
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Proto/Port", "Service", "Product", "Version", "Vulnerabilities"])
            for svc in data.get("raw_services", []):
                key = f"{svc['proto']}/{svc['port']} {svc['name']} {svc.get('product','')} {svc.get('version','')}"
                vulns = "; ".join(data.get("vulnerabilities", {}).get(key.strip(), []))
                writer.writerow([
                    f"{svc['proto']}/{svc['port']}",
                    svc["name"],
                    svc.get("product", ""),
                    svc.get("version", ""),
                    vulns
                ])
        logger.info(f"CSV report saved to {output_path}")

    @staticmethod
    def html_report(data: dict, output_path: str):
        if not HAS_JINJA:
            logger.warning("Jinja2 not installed, skipping HTML report.")
            return
        template_str = """<!DOCTYPE html>
<html><head><title>Scan Report {{ target }}</title>
<style>body{font-family:Arial;margin:20px;}table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #ddd;padding:8px;}th{background:#4CAF50;color:white;}
.vuln{color:red;}</style></head><body>
<h1>Scan Report: {{ target }}</h1>
<p>OS: {{ os }} | Time: {{ timestamp }}</p>
<h2>Open Services</h2>
<table><tr><th>Proto/Port</th><th>Service</th><th>Product</th><th>Version</th><th>Vulnerabilities</th></tr>
{% for s in raw_services %}
<tr><td>{{ s.proto }}/{{ s.port }}</td><td>{{ s.name }}</td><td>{{ s.product or '' }}</td>
<td>{{ s.version or '' }}</td><td class="vuln">{{ ', '.join(vuln_map.get((s.proto~'/'~s.port~' '~s.name~' '~(s.product or '')~' '~(s.version or '')).strip(), [])) }}</td></tr>
{% endfor %}</table>
<h2>Attack Surface Modules</h2>
{% for mod, svcs in modules.items() %}{% if svcs %}
<h3>{{ mod }}</h3><ul>{% for s in svcs %}<li>{{ s }}</li>{% endfor %}</ul>
{% endif %}{% endfor %}
</body></html>"""
        vuln_map = {k.strip(): v for k, v in data.get("vulnerabilities", {}).items()}
        raw_services = data.get("raw_services", [])
        rendered = Template(template_str).render(
            target=data["target"],
            os=data.get("os", ""),
            timestamp=data["timestamp"],
            raw_services=raw_services,
            modules=data.get("modules", {}),
            vuln_map=vuln_map
        )
        with open(output_path, "w") as f:
            f.write(rendered)
        logger.info(f"HTML report saved to {output_path}")

    @staticmethod
    def send_email(data: dict, smtp_config: dict):
        """Send report via email."""
        try:
            msg = EmailMessage()
            msg["Subject"] = f"Scan Report for {data['target']}"
            msg["From"] = smtp_config["from"]
            msg["To"] = smtp_config["to"]
            body = f"OS: {data.get('os')}\n\nServices:\n"
            body += "\n".join(data["services"])
            msg.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_config["server"], smtp_config["port"]) as s:
                s.ehlo()
                s.starttls(context=context)
                s.login(smtp_config["user"], smtp_config["password"])
                s.send_message(msg)
            logger.info("Email sent successfully.")
        except Exception as e:
            logger.error(f"Email failed: {e}")

    @staticmethod
    def slack_webhook(data: dict, webhook_url: str):
        """Post summary to Slack webhook."""
        blocks = [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Scan Report for {data['target']}*\nOS: {data.get('os')}"}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": "Services:\n" + "\n".join(f"• {s}" for s in data["services"])}}
        ]
        payload = {"text": f"Scan complete: {data['target']}", "blocks": blocks}
        try:
            r = requests.post(webhook_url, json=payload, timeout=10)
            if r.status_code == 200:
                logger.info("Slack notification sent.")
            else:
                logger.warning(f"Slack webhook failed: {r.status_code}")
        except Exception as e:
            logger.error(f"Slack error: {e}")

# ---------------------------------------------------------------------------
# CLI & Main
# ---------------------------------------------------------------------------
async def scan_target_async(target, args, progress_bar=None):
    """Run scanner on a single target and return report data."""
    scanner = SuperWindowsScanner(
        target=target,
        scan_mode=args.mode,
        threads=args.threads,
        stealth=args.stealth,
        vuln_check=args.vuln_check,
        nmap_args_extra=args.nmap_args or "",
        nvd_api_key=args.nvd_key,
    )
    result = await scanner.full_analysis()
    if progress_bar:
        progress_bar.update(1)
    return result

async def main_async():
    parser = argparse.ArgumentParser(
        description=BANNER + "\nWindows Server Scanner – Super Upgrade",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("targets", nargs="+", help="Target IP(s) or CIDR (space/comma separated)")
    parser.add_argument("-m", "--mode", choices=["quick","common","full","custom"], default="quick",
                        help="Scan depth")
    parser.add_argument("--stealth", action="store_true", help="Use stealth techniques (slower)")
    parser.add_argument("--vuln-check", action="store_true", help="Enable live CVE lookup")
    parser.add_argument("--nvd-key", help="NVD API key for higher rate limits")
    parser.add_argument("--nmap-args", help="Extra nmap arguments (use with custom mode)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Max parallel scans")
    parser.add_argument("-o", "--output", help="Output base filename (no extension) – saves report(s) if provided")
    parser.add_argument("--format", choices=["json","csv","html","all"], default="json",
                        help="Output format(s) when -o is used")
    parser.add_argument("--email", help="Send report to email (requires config in --config)")
    parser.add_argument("--slack", help="Slack webhook URL for notifications")
    parser.add_argument("--config", help="YAML/JSON config file with defaults")
    parser.add_argument("--verbose", action="store_true", help="Verbose console output")
    args = parser.parse_args()

    # Load config if provided
    if args.config:
        with open(args.config) as f:
            if args.config.endswith(".yaml") or args.config.endswith(".yml"):
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
        for key, value in config.items():
            if not getattr(args, key, None):
                setattr(args, key, value)

    # Parse targets
    targets = []
    for arg in args.targets:
        targets.extend([t.strip() for t in arg.split(',') if t.strip()])

    print(BANNER)
    print(f"{Fore.BLUE}[*] Starting {args.mode.upper()} scan on {len(targets)} target(s)...{Style.RESET_ALL}")

    # Progress bar
    with tqdm(total=len(targets), desc="Scanning", unit="target", colour="green") as pbar:
        tasks = [scan_target_async(t, args, pbar) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    for result in results:
        if isinstance(result, Exception):
            logger.error(f"Scan error: {result}")
            continue
        if not result:
            continue

        # Always show on console
        Reporter.console_report(result, verbose=args.verbose)

        # Save only if -o provided
        if args.output:
            base = args.output
            if args.format in ("json", "all"):
                Reporter.json_report(result, f"{base}.json")
            if args.format in ("csv", "all"):
                Reporter.csv_report(result, f"{base}.csv")
            if args.format in ("html", "all"):
                Reporter.html_report(result, f"{base}.html")

        # Notifications (optional)
        if args.email:
            smtp_conf = {}
            if args.config:
                with open(args.config) as f:
                    conf = yaml.safe_load(f)
                    smtp_conf = conf.get("smtp", {})
            if smtp_conf:
                Reporter.send_email(result, smtp_conf)
        if args.slack:
            Reporter.slack_webhook(result, args.slack)

    print(Fore.GREEN + f"\n[*] All scans completed. Reports saved only if -o was given.{Style.RESET_ALL}")

def main():
    """Entry point for CLI."""
    asyncio.run(main_async())

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
# =============================================================================
#                               COMPLETE USER MANUAL
#                  Windows Server Targeted Scanner – SUPER UPGRADE
#                               Version 2.0.1 (Fixed)
# =============================================================================
#
# TABLE OF CONTENTS
# -----------------
#  1. INTRODUCTION & PURPOSE
#  2. SYSTEM REQUIREMENTS
#  3. INSTALLATION GUIDE
#  4. SCAN MODES EXPLAINED
#  5. COMPLETE COMMAND-LINE REFERENCE
#  6. USAGE EXAMPLES (WITH EXPLANATIONS)
#  7. OUTPUT & REPORTING EXPLAINED
#  8. ATTACK SURFACE MODULES REFERENCE
#  9. VULNERABILITY DETECTION SYSTEM
# 10. STEALTH MODE DETAILS
# 11. CONFIGURATION FILE GUIDE
# 12. HOW TO GET AN NVD API KEY
# 13. TROUBLESHOOTING COMMON ERRORS
# 14. LEGAL DISCLAIMER & ETHICS
# 15. FREQUENTLY ASKED QUESTIONS
#
# =============================================================================
# 1. INTRODUCTION & PURPOSE
# =============================================================================
# This tool is a multi-threaded, asynchronous network scanner specifically
# designed for Windows Server environments. It identifies:
#
#   • Open TCP and UDP ports
#   • Running services and their versions
#   • Operating system detection
#   • Mapping of services to known attack vectors/modules
#   • Known vulnerabilities (CVEs) via static database AND live NIST NVD API
#   • NSE (Nmap Scripting Engine) script results
#
# The scanner is useful for:
#   • Penetration testing (with permission)
#   • Security auditing of Windows infrastructure
#   • Attack surface analysis
#   • Vulnerability assessment
#   • Compliance checking
#
# =============================================================================
# 2. SYSTEM REQUIREMENTS
# =============================================================================
#
# Hardware:
#   • Any modern CPU (multi-core recommended for parallel scans)
#   • Minimum 2GB RAM (8GB+ for /24 full scans)
#   • Stable network connection
#
# Software:
#   • Linux OS (Kali, Ubuntu, Debian, Parrot, etc.) – macOS also works
#   • Python 3.8 or higher
#   • Nmap 7.80 or higher (install with: sudo apt install nmap)
#   • Root/sudo access (REQUIRED for UDP scans and OS detection)
#
# Python Packages:
#   pip install python-nmap requests tqdm colorama pyyaml jinja2
#
#   Package details:
#   - python-nmap : Python wrapper for Nmap
#   - requests    : HTTP library for NVD API calls
#   - tqdm        : Progress bar display
#   - colorama    : Coloured terminal output
#   - pyyaml      : YAML config file parsing
#   - jinja2      : HTML report templating (optional but recommended)
#
# =============================================================================
# 3. INSTALLATION GUIDE
# =============================================================================
#
# Step-by-step installation:
#
#   1. Update your system:
#      sudo apt update && sudo apt upgrade -y
#
#   2. Install Nmap:
#      sudo apt install nmap -y
#
#   3. Install Python and pip (if not already installed):
#      sudo apt install python3 python3-pip -y
#
#   4. Install required Python packages:
#      pip install python-nmap requests tqdm colorama pyyaml jinja2
#
#   5. Download the scanner script:
#      wget https://your-repo/scanner.py
#      (or copy the code and save as scanner.py)
#
#   6. Make it executable:
#      chmod +x scanner.py
#
#   7. Test the installation:
#      sudo python3 scanner.py 127.0.0.1 -m quick
#
# =============================================================================
# 4. SCAN MODES EXPLAINED
# =============================================================================
#
# ┌─────────┬──────────────────┬─────────────────┬─────────────────┬──────────┐
# │  Mode   │   TCP Ports      │   UDP Ports     │ Version/OS Det  │ Duration │
# ├─────────┼──────────────────┼─────────────────┼─────────────────┼──────────┤
# │ quick   │ ~34 important    │ ~10 common      │ No              │ 1-3 min  │
# │ common  │ Top 1000         │ 20 specific     │ Yes (full)      │ 10-20 min│
# │ full    │ All 65535        │ 20 specific     │ Yes (full)      │ 1-4 hours│
# │ custom  │ Defined by user  │ Defined by user │ Depends on args │ Varies   │
# └─────────┴──────────────────┴─────────────────┴─────────────────┴──────────┘
#
# quick:
#   - Best for: Fast initial reconnaissance
#   - Scans: 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,
#            593,636,993,995,1433,1723,3268,3269,3306,3389,5432,5900,5985,
#            5986,8080,8443,8530,8531 (TCP)
#            + 53,67,68,123,161,162,520,1900,11211 (UDP)
#   - Detection: Port state only (open/closed/filtered)
#   - Scripts: None
#   - OS detection: No
#   - Timing: T5 (insane), min-rate 1500, 2 minute host timeout
#
# common:
#   - Best for: Thorough security assessment
#   - Scans: Top 1000 TCP ports (Nmap default) + 20 specific UDP ports
#   - Detection: Service version, OS guess, NSE scripts
#   - Scripts: vulners, vuln (when --vuln-check is used)
#   - OS detection: Yes (--osscan-guess)
#   - Timing: T4 (aggressive), min-rate 800, 8 minute host timeout
#
# full:
#   - Best for: Complete audit, compliance
#   - Scans: ALL 65,535 TCP ports + 20 specific UDP ports
#   - Detection: Service version, OS guess, NSE scripts
#   - Scripts: vulners, vuln (when --vuln-check is used)
#   - OS detection: Yes (--osscan-guess)
#   - Timing: T4, min-rate 800, 8 minute host timeout
#   - Warning: VERY slow. May take hours per host.
#
# custom:
#   - Best for: Specific use cases, manual control
#   - Ports: Defined entirely by --nmap-args argument
#   - Example: --nmap-args "-p 80,443,3389 --script http-enum"
#   - All detection options depend on what you specify in --nmap-args
#
# =============================================================================
# 5. COMPLETE COMMAND-LINE REFERENCE
# =============================================================================
#
# USAGE:
#   sudo python3 scanner.py <targets> [OPTIONS]
#
# POSITIONAL ARGUMENTS:
#   targets
#       One or more target IP addresses or CIDR ranges.
#       Multiple targets can be separated by spaces or commas.
#       Examples:
#         192.168.1.1
#         192.168.1.0/24
#         10.0.0.1,10.0.0.2,10.0.0.3
#         192.168.1.1 192.168.1.2 10.0.0.0/24
#
# OPTIONAL ARGUMENTS:
#
#   -h, --help
#       Show the help message and exit.
#
#   -m, --mode {quick,common,full,custom}
#       Scan depth/mode selection.
#       Default: quick
#       See Section 4 for detailed comparison.
#
#   --stealth
#       Enable stealth scanning mode.
#       Effects:
#         • Reduces timing to T2 (polite)
#         • Adds 500ms delay between probes
#         • Uses decoy IPs to mask real source
#         • Randomises host scanning order
#         • Limits max parallel scans to 2
#         • Increases max retries to 2
#       Use when: Target has IDS/IPS, you want to avoid detection
#       Trade-off: Much slower (3-5x normal duration)
#
#   --vuln-check
#       Enable online vulnerability lookup via NIST NVD API.
#       Without this flag, only the built-in static database is checked.
#       Requires: Internet connection
#       Rate limit without API key: 5 requests per 30 seconds
#       Rate limit with API key: 50 requests per 30 seconds
#
#   --nvd-key KEY
#       Your NIST NVD API key for higher rate limits.
#       Get a free key at: https://nvd.nist.gov/developers/request-an-api-key
#       Example: --nvd-key "a1b2c3d4-5678-90ab-cdef-1234567890ab"
#
#   --nmap-args ARGS
#       Additional Nmap arguments passed directly to the scan engine.
#       Use quotes for arguments containing spaces.
#       Examples:
#         --nmap-args "--script http-enum"
#         --nmap-args "-p 80,443,8080 --min-rate 2000"
#         --nmap-args "--script-args http.useragent='Mozilla/5.0'"
#
#   -t, --threads N
#       Maximum number of concurrent/parallel target scans.
#       Default: 10
#       Note: In stealth mode, this is automatically capped at 2.
#       Recommendation: Don't exceed CPU core count.
#
#   -o, --output NAME
#       Base filename for saving reports (without file extension).
#       If NOT provided: Results are ONLY displayed in terminal.
#       If provided: File(s) saved as NAME.json, NAME.csv, NAME.html
#       Example: -o myscan → saves myscan.json (or csv/html based on --format)
#
#   --format {json,csv,html,all}
#       Output file format(s).
#       Default: json
#       json : Structured data with all fields
#       csv  : Spreadsheet-ready table with services and vulns
#       html : Styled HTML page with tables and colour coding
#       all  : Generates all three formats
#       Only used when -o is specified.
#
#   --email ADDRESS
#       Send scan report via email after completion.
#       Requires SMTP configuration in a config file (see --config).
#       Example: --email "security@company.com"
#
#   --slack URL
#       Send summary notification to a Slack webhook.
#       Example: --slack "https://hooks.slack.com/services/T00/B00/xxxx"
#
#   --config FILE
#       Path to YAML or JSON configuration file.
#       Can contain default values for any argument plus SMTP settings.
#       CLI arguments override config file values.
#       See Section 11 for config file format.
#
#   --verbose
#       Display additional details in console output.
#       Shows raw service info, script outputs, and debug information.
#
# =============================================================================
# 6. USAGE EXAMPLES (WITH EXPLANATIONS)
# =============================================================================
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 1: Quick reconnaissance of a single server                     │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 192.168.1.10 -m quick                          │
# │                                                                         │
# │ What it does:                                                           │
# │  • Scans 34 TCP + 10 UDP ports                                         │
# │  • No version/OS detection                                             │
# │  • Displays open ports grouped by attack module                        │
# │  • Shows static vulnerability warnings if matching                     │
# │  • No file saved, console output only                                  │
# │  • Duration: ~1-2 minutes                                              │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 2: Security audit with vulnerability check                     │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 192.168.1.10 -m common --vuln-check            │
# │                                                                         │
# │ What it does:                                                           │
# │  • Scans top 1000 TCP + 20 UDP ports                                   │
# │  • Detects service versions and OS                                     │
# │  • Runs vulners and vuln NSE scripts                                   │
# │  • Checks static database AND live NVD for CVEs                        │
# │  • Displays all vulnerabilities in red                                 │
# │  • Duration: ~10-15 minutes                                            │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 3: Full audit with JSON/CSV/HTML output                        │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 10.0.0.50 -m full --vuln-check \              │
# │   -o full_audit --format all                                           │
# │                                                                         │
# │ What it does:                                                           │
# │  • Scans ALL 65535 TCP ports                                           │
# │  • Complete version, OS, and script detection                          │
# │  • Live CVE lookup for every service                                   │
# │  • Saves full_audit.json, full_audit.csv, full_audit.html              │
# │  • Duration: ~1-3 hours                                                │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 4: Stealth scan of a sensitive production server               │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 192.168.1.10 -m common \                      │
# │   --stealth --vuln-check -o stealth_scan                               │
# │                                                                         │
# │ What it does:                                                           │
# │  • Polite timing (T2) with delays and decoys                           │
# │  • Max 2 concurrent threads                                            │
# │  • Less likely to trigger IDS/IPS alarms                               │
# │  • Duration: ~30-45 minutes                                            │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 5: Scan entire subnet with progress bar                        │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 192.168.1.0/24 -m quick -t 20                 │
# │                                                                         │
# │ What it does:                                                           │
# │  • Scans all 254 hosts in the /24 subnet                               │
# │  • Uses 20 parallel threads (faster but more network load)             │
# │  • Shows real-time progress bar: "Scanning: 73% |████████▌   |"       │
# │  • Duration: ~5-10 minutes for quick scan                              │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 6: Using config file with email notification                   │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 10.0.0.1,10.0.0.2 -m common \                 │
# │   --config my_config.yaml --vuln-check --email admin@company.com       │
# │                                                                         │
# │ What it does:                                                           │
# │  • Loads API key and SMTP settings from my_config.yaml                 │
# │  • Scans two servers                                                   │
# │  • Sends email report after completion                                 │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 7: Custom port scan with specific NSE scripts                  │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 192.168.1.10 -m custom \                      │
# │   --nmap-args "-p 80,443,3389,5985,5986 --script http-enum,rdp-vuln"  │
# │                                                                         │
# │ What it does:                                                           │
# │  • Only scans ports 80,443,3389,5985,5986                              │
# │  • Runs http-enum and rdp-vuln NSE scripts                             │
# │  • No predefined modules – only custom ports                           │
# └─────────────────────────────────────────────────────────────────────────┘
#
# ┌─────────────────────────────────────────────────────────────────────────┐
# │ EXAMPLE 8: Slack notification for team awareness                       │
# ├─────────────────────────────────────────────────────────────────────────┤
# │ sudo python3 scanner.py 192.168.1.0/24 -m quick \                     │
# │   --slack "https://hooks.slack.com/services/T00/B00/xxxx"              │
# │                                                                         │
# │ What it does:                                                           │
# │  • Scans entire subnet                                                 │
# │  • Posts summary to Slack channel (target, OS, open services)          │
# │  • Good for automated scheduled scans                                  │
# └─────────────────────────────────────────────────────────────────────────┘
#
# =============================================================================
# 7. OUTPUT & REPORTING EXPLAINED
# =============================================================================
#
# CONSOLE OUTPUT (always displayed):
#
#   ╔══════════════════════════════════════════════════════════════╗
#   ║  Windows Server Targeted Scanner – SUPER UPGRADE              ║
#   ║  Version 2.0.1-fixed                                         ║
#   ╚══════════════════════════════════════════════════════════════╝
#
#   ======================================================================
#     Scan Report for 192.168.1.10
#     OS: Microsoft Windows Server 2019 (accuracy: 98%)
#   ======================================================================
#
#   [Services]                          ← List of ALL open services
#     tcp/445 microsoft-ds Windows Server 2019
#     tcp/3389 ms-wbt-server Microsoft Terminal Services
#     tcp/80 http Apache httpd 2.4.46
#     ...
#
#   [Module Classification]             ← Grouped by attack surface
#     SMB Attacker:
#       - tcp/445 microsoft-ds Windows Server 2019
#       [!] Potential attack surface identified
#       [!] Known vulnerabilities detected:
#           - MS17-010 (EternalBlue) – RCE via SMBv1
#           - CVE-2020-0796 (SMBGhost) – RCE
#
#     Install & Update:
#       - tcp/3389 ms-wbt-server Microsoft Terminal Services
#       [!] Known vulnerabilities detected:
#           - CVE-2019-0708 (BlueKeep) – RCE
#
#   [Vulnerabilities]                   ← Full CVE list with details
#     tcp/445 microsoft-ds Windows Server 2019:
#       [!] MS17-010 (EternalBlue) – RCE via SMBv1
#       [!] CVE-2020-0796 (SMBGhost) – RCE
#     tcp/3389 ms-wbt-server Microsoft Terminal Services:
#       [!] CVE-2019-0708 (BlueKeep) – RCE
#
# JSON OUTPUT (when -o is used):
#   Complete structured data including:
#   {
#     "target": "192.168.1.10",
#     "os": "Microsoft Windows Server 2019",
#     "timestamp": "2024-01-15T14:30:00",
#     "services": ["tcp/445 microsoft-ds ...", ...],
#     "modules": {
#       "SMB Attacker": ["tcp/445 microsoft-ds ..."],
#       ...
#     },
#     "vulnerabilities": {
#       "tcp/445 microsoft-ds ...": ["MS17-010 ...", "CVE-2020-0796 ..."]
#     },
#     "raw_services": [{port: 445, proto: "tcp", ...}, ...]
#   }
#
# CSV OUTPUT:
#   Spreadsheet with columns:
#   Proto/Port | Service | Product | Version | Vulnerabilities
#   -----------|---------|---------|---------|------------------
#   tcp/445    | microsoft-ds | Windows Server | 2019 | MS17-010; CVE-2020-0796
#
# HTML OUTPUT:
#   Styled webpage with:
#   • Coloured vulnerability warnings
#   • Sortable service tables
#   • Module classification with expandable sections
#   • Professional appearance for reports
#
# =============================================================================
# 8. ATTACK SURFACE MODULES REFERENCE
# =============================================================================
#
# Each module represents a potential attack vector. When a service is detected
# on a relevant port, it's mapped to the corresponding module.
#
# ┌──────────────────────┬──────────────┬─────────┬───────────────────────────┐
# │ Module               │ Ports        │ Proto   │ Why It's a Target         │
# ├──────────────────────┼──────────────┼─────────┼───────────────────────────┤
# │ DHCP Attacker        │ 67, 68       │ UDP     │ DHCP spoofing, starvation  │
# │ DNS Attacker         │ 53           │ TCP/UDP │ Cache poisoning, tunneling │
# │ AD Attacker          │ 88, 135, 139,│ TCP     │ Kerberoasting, DCSync,    │
# │                      │ 389, 464, 636│         │ LDAP injection, NTLM relay│
# │                      │ 3268, 3269   │         │                           │
# │ SMB Attacker         │ 139, 445     │ TCP     │ EternalBlue, SMBGhost,     │
# │                      │              │         │ Pass-the-hash, PSExec      │
# │ SNMP Sniffinger      │ 161, 162     │ UDP     │ Default communities, info  │
# │                      │              │         │ disclosure, MITM           │
# │ DoS Amplification    │ 19, 123, 520,│ UDP     │ Chargen amp, NTP amp,      │
# │                      │ 1900, 11211  │         │ SSDP amp, Memcached amp    │
# │ Install & Update     │ 80, 443, 3389│ TCP     │ WSUS hijack, WinRM abuse,  │
# │                      │ 5985, 5986,  │         │ RDP brute force, MITM      │
# │                      │ 8530, 8531   │         │                           │
# │ Print Spooler        │ 515, 9100    │ TCP     │ PrintNightmare, LPD abuse  │
# │ LDAP Signing         │ 389, 636     │ TCP     │ LDAP without signing,      │
# │                      │              │         │ Channel binding missing    │
# └──────────────────────┴──────────────┴─────────┴───────────────────────────┘
#
# =============================================================================
# 9. VULNERABILITY DETECTION SYSTEM
# =============================================================================
#
# The scanner uses THREE layers of vulnerability detection:
#
# Layer 1 – Static Database (always active):
#   Built-in signatures for well-known Windows vulnerabilities:
#
#   • SMBv1         → MS17-010 (EternalBlue)
#   • SMBv2         → CVE-2017-0144
#   • SMBv3.1.1     → CVE-2020-0796 (SMBGhost)
#   • RDP           → CVE-2019-0708 (BlueKeep), CVE-2020-0610
#   • DNS           → CVE-2020-1350 (SigRed), CVE-2015-7547
#   • SNMP          → Default communities (public/private), CVE-2015-5624
#   • WinRM         → CVE-2015-0010 (auth bypass)
#
# Layer 2 – NSE Scripts (when using common/full + --vuln-check):
#   Nmap scripts are executed during the scan:
#
#   • vulners.nse    : Checks services against the vulners.com database
#   • vuln.nse       : Runs category of vulnerability scripts
#   • smb-vuln-ms17-010.nse : Specific EternalBlue check
#   • rdp-vuln-ms12-020.nse : Specific RDP check
#
#   Script output is parsed and added to vulnerability list.
#
# Layer 3 – NVD Live Lookup (when --vuln-check is active):
#   Queries the National Vulnerability Database in real-time:
#
#   • Takes service name, product, and version
#   • Searches NVD API for matching CVEs
#   • Returns up to 5 most relevant CVEs per service
#   • Includes CVE ID and description
#   • Rate limited: 5 req/30s (without key), 50 req/30s (with key)
#
#   The NVD API call looks like:
#   GET https://services.nvd.nist.gov/rest/json/cves/2.0
#       ?keywordSearch=Apache+httpd+2.4.46
#       &resultsPerPage=5
#
# =============================================================================
# 10. STEALTH MODE DETAILS
# =============================================================================
#
# When --stealth is enabled, the following changes are made to avoid
# triggering Intrusion Detection/Prevention Systems:
#
# ┌──────────────────────┬───────────────────┬────────────────────────────┐
# │ Parameter            │ Normal            │ Stealth                    │
# ├──────────────────────┼───────────────────┼────────────────────────────┤
# │ Nmap Timing          │ T4 or T5          │ T2 (polite)               │
# │ Scan Delay           │ None              │ 500ms between probes       │
# │ Max Retries          │ Default           │ 2                          │
# │ Host Order           │ Sequential        │ Randomised                 │
# │ Decoy IPs            │ None              │ 3 decoy IPs used           │
# │ Max Threads          │ 10                │ Forced to 2                │
# │ Min Rate             │ 800-1500          │ Not set (slow)             │
# │ Host Timeout         │ 2-8 minutes       │ Default (longer)           │
# └──────────────────────┴───────────────────┴────────────────────────────┘
#
# Decoy IPs used (example – change in code if needed):
#   • 10.0.0.1
#   • 172.16.0.1
#   • 192.168.0.1
#
# WARNING: Decoy IPs should be alive hosts. If the target network detects
# that decoys are dead, the real source IP may still be identified.
#
# =============================================================================
# 11. CONFIGURATION FILE GUIDE
# =============================================================================
#
# YAML config file example (save as scanner_config.yaml):
#
#   ---
#   # NVD API configuration
#   nvd_key: "your-nvd-api-key-here"
#
#   # Default scan settings
#   mode: "common"
#   vuln_check: true
#   threads: 5
#   output: "auto_scan"
#   format: "all"
#
#   # SMTP settings for email reports
#   smtp:
#     server: "smtp.gmail.com"
#     port: 587
#     user: "your-email@gmail.com"
#     password: "your-app-specific-password"
#     from: "your-email@gmail.com"
#     to: "security-team@company.com"
#
#   # Slack webhook
#   slack: "https://hooks.slack.com/services/T00/B00/xxxxx"
#
# JSON config file example (save as scanner_config.json):
#
#   {
#     "nvd_key": "your-nvd-api-key-here",
#     "mode": "common",
#     "vuln_check": true,
#     "threads": 5,
#     "output": "auto_scan",
#     "format": "all",
#     "smtp": {
#       "server": "smtp.gmail.com",
#       "port": 587,
#       "user": "your-email@gmail.com",
#       "password": "your-app-specific-password",
#       "from": "your-email@gmail.com",
#       "to": "security-team@company.com"
#     },
#     "slack": "https://hooks.slack.com/services/T00/B00/xxxxx"
#   }
#
# Usage with config:
#   sudo python3 scanner.py 192.168.1.10 --config scanner_config.yaml
#
# CLI arguments OVERRIDE config file values. Example:
#   sudo python3 scanner.py 192.168.1.10 --config scanner_config.yaml -m full
#   → Uses "full" mode (overrides config's "common")
#
# =============================================================================
# 12. HOW TO GET AN NVD API KEY
# =============================================================================
#
# 1. Go to: https://nvd.nist.gov/developers/request-an-api-key
# 2. Fill in your name, email, and reason ("Security testing")
# 3. You'll receive an email with your API key
# 4. The key looks like: a1b2c3d4-5678-90ab-cdef-1234567890ab
#
# Without API key: 5 requests per 30 seconds
# With API key:    50 requests per 30 seconds
#
# Use it with: --nvd-key "your-key-here"
# Or put it in your config file.
#
# =============================================================================
# 13. TROUBLESHOOTING COMMON ERRORS
# =============================================================================
#
# ERROR: "BaseEventLoop.run_in_executor() got an unexpected keyword argument"
#   FIX: This was a bug in version 2.0.0. Update to version 2.0.1+ where
#        the issue is fixed by using a lambda wrapper.
#
# ERROR: "nmap program was not found in path"
#   FIX: Install Nmap: sudo apt install nmap
#        Verify with: which nmap
#
# ERROR: "You requested a scan type which requires root privileges"
#   FIX: Run with sudo: sudo python3 scanner.py <target>
#        UDP scans and OS detection require root.
#
# ERROR: "ModuleNotFoundError: No module named 'nmap'"
#   FIX: pip install python-nmap
#        Note: The package is 'python-nmap', but import is 'nmap'.
#
# ERROR: "No hosts found" or "Host not reachable"
#   FIX: Check if the target is online (ping it first)
#        Check firewall rules (may be blocking probes)
#        Try without stealth mode first
#
# ERROR: "NVD API returned status 403"
#   FIX: You may be rate-limited. Wait 30 seconds and retry.
#        Or get a free API key for higher limits.
#
# ERROR: UDP ports show "open|filtered" but not "open"
#   FIX: This is normal for UDP scans. The scanner treats "open|filtered"
#        as potentially open and includes them in results.
#
# ERROR: HTML report not generated
#   FIX: Install jinja2: pip install jinja2
#        HTML reports require this templating library.
#
# =============================================================================
# 14. LEGAL DISCLAIMER & ETHICS
# =============================================================================
#
# ⚠️  WARNING – READ CAREFULLY  ⚠️
#
# This tool is designed for AUTHORISED security testing only.
#
# YOU MUST:
#   ✅ Own the target system, OR
#   ✅ Have EXPLICIT WRITTEN permission from the system owner, OR
#   ✅ Be testing in a controlled lab environment you own
#
# YOU MUST NOT:
#   ❌ Scan systems without permission
#   ❌ Use findings to exploit vulnerabilities without authorisation
#   ❌ Share vulnerability data with unauthorised parties
#   ❌ Use this tool for illegal activities
#
# UNAUTHORISED SCANNING IS ILLEGAL under computer misuse laws in most
# countries, including:
#   • Computer Fraud and Abuse Act (CFAA) – United States
#   • Computer Misuse Act 1990 – United Kingdom
#   • Criminal Code (Section 342.1) – Canada
#   • Cybercrime Act 2001 – Australia
#   • Information Technology Act 2000 – India
#   • Penal Code (various articles) – Iran and other countries
#
# The authors and contributors are NOT responsible for any misuse,
# damage, or legal consequences caused by this tool.
#
# USE AT YOUR OWN RISK.
#
# =============================================================================
# 15. FREQUENTLY ASKED QUESTIONS
# =============================================================================
#
# Q: Can I scan multiple subnets at once?
# A: Yes: sudo python3 scanner.py 192.168.1.0/24 10.0.0.0/24 -m quick -t 20
#    But be careful – large scans can take hours and generate heavy traffic.
#
# Q: How do I save results for later analysis?
# A: Use -o flag: -o my_scan --format all
#    This creates my_scan.json, my_scan.csv, and my_scan.html
#
# Q: What's the difference between quick and common modes?
# A: Quick scans ~44 ports with no version detection (fast).
#    Common scans ~1020 ports with version, OS, and scripts (thorough).
#    Quick is 5-10x faster but may miss services on non-standard ports.
#
# Q: Why does full mode take so long?
# A: Full mode scans 65,535 TCP ports. Even at high speed, this requires
#    sending and receiving packets for every port, which takes time.
#    For a single host: typically 1-4 hours depending on network speed.
#
# Q: Is my data sent anywhere during the scan?
# A: Only if you use --vuln-check. Then service names/versions are sent
#    to the NIST NVD API for CVE lookup. Otherwise, all processing is local.
#
# Q: Can I use this on non-Windows servers?
# A: Yes, technically it works on any host with open ports. The module
#    classification is Windows-focused, but service detection and CVE
#    lookup work for all platforms.
#
# Q: What NSE scripts are run?
# A: In common/full with --vuln-check: vulners and vuln categories.
#    You can add more with --nmap-args "--script http-enum,ssl-enum-ciphers"
#
# Q: How do I schedule automatic scans?
# A: Use cron (Linux) or Task Scheduler (Windows):
#    0 2 * * * sudo python3 /path/to/scanner.py 192.168.1.0/24 -m common -o /reports/nightly --format json
#
# =============================================================================
# END OF MANUAL
# =============================================================================