#!/usr/bin/env bash
#
# Project Nemesis — a safe, educational network-security dashboard
# I created this project for the software project course at Karaj Azad University.
#
# Run the script with root privileges for attack modules to work.

set -o pipefail

# --- Version & log -----------------------------------------------------------
readonly VERSION='3.0.0'
readonly LOGFILE="${HOME}/.nemesis.log"

# --- Locate script directory -------------------------------------------------
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

# --- Tool paths & checks -----------------------------------------------------
readonly PIG_SCRIPT="${SCRIPT_DIR}/DHCP/pig.py"
readonly DNSFORGE_MODULE="DNS.dnsforge"   # Python module path

# Verify DHCP tool
if [[ ! -f "$PIG_SCRIPT" ]]; then
  printf 'ERROR: %s not found.\n' "$PIG_SCRIPT" >&2
  printf 'Make sure pig.py is inside the DHCP folder next to this script.\n' >&2
  exit 1
fi

# Verify DNS tool (by trying to import it)
cd "$SCRIPT_DIR" || exit 1
if ! python3 -c "import ${DNSFORGE_MODULE}" 2>/dev/null; then
  printf 'ERROR: %s module not found in %s\n' "$DNSFORGE_MODULE" "$SCRIPT_DIR" >&2
  printf 'Make sure dnsforge.py is inside the DNS folder.\n' >&2
  exit 1
fi
cd - >/dev/null

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

# --- Common attack helpers ---------------------------------------------------
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

get_interface() {
  # reuse SAVED_IFACE if set and user confirms
  if [[ -n "$SAVED_IFACE" ]]; then
    printf '%b' "${CYAN}Use saved interface ${BOLD}$SAVED_IFACE${RESET}? [Y/n]: "
    IFS= read -r use_saved
    if [[ "${use_saved,,}" != "n" && "${use_saved,,}" != "no" ]]; then
      echo "$SAVED_IFACE"
      return
    fi
  fi
  printf '%b' "${CYAN}Network interface (e.g. eth0, vboxnet0): ${RESET}"
  IFS= read -r iface
  if [[ -n "$iface" ]]; then
    SAVED_IFACE="$iface"
    echo "$iface"
  else
    return 1
  fi
}

# ==================== DHCP ATTACK LAB (existing) =============================

run_pig() {
  local args=("$@")
  local iface=""
  local cmd=()

  # Try to extract interface from args if present
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "-i" ]]; then
      iface="${args[$i+1]}"
      break
    fi
  done

  if [[ -z "$iface" ]]; then
    iface=$(get_interface) || { printf '%b\n' "${RED}No interface given, aborting.${RESET}"; sleep 1; return 1; }
    cmd+=("-i" "$iface")
  else
    SAVED_IFACE="$iface"
  fi

  local full_cmd=("$PIG_SCRIPT" "${args[@]}" "${cmd[@]}")
  local desc="${full_cmd[*]}"

  clear_screen
  logo
  banner "Execute DHCP Attack"
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

advanced_pig_wizard() {
  local pig_args=()
  local choice=""

  clear_screen
  logo
  banner "Advanced DHCP Attack Configuration"
  printf '%b\n' "${MUTED}Configure each option. Leave empty for default.${RESET}\n"

  printf '%b' "${CYAN}Verbosity (0-99, default 10): ${RESET}"
  IFS= read -r verb
  [[ -n "$verb" ]] && pig_args+=("-v" "$verb")

  printf '%b' "${CYAN}IPv6 mode? [y/N]: ${RESET}"
  IFS= read -r v6
  if [[ "${v6,,}" == "y" ]]; then
    pig_args+=("-6")
    printf '%b' "${CYAN}  RapidCommit? [y/N]: ${RESET}"
    IFS= read -r rapid
    [[ "${rapid,,}" == "y" ]] && pig_args+=("-1")
  fi

  printf '%b' "${CYAN}Custom MAC list (comma separated): ${RESET}"
  IFS= read -r macs
  [[ -n "$macs" ]] && pig_args+=("-s" "$macs")

  printf '%b' "${CYAN}Identical Ethernet & DHCP MAC? [y/N]: ${RESET}"
  IFS= read -r same_mac
  [[ "${same_mac,,}" == "y" ]] && pig_args+=("-S")

  printf '%b' "${CYAN}Custom request options (e.g. 21,22,23): ${RESET}"
  IFS= read -r req_opts
  [[ -n "$req_opts" ]] && pig_args+=("-O" "$req_opts")

  printf '%b' "${CYAN}Fuzzing? [y/N]: ${RESET}"
  IFS= read -r fuzz
  [[ "${fuzz,,}" == "y" ]] && pig_args+=("-f")

  printf '%b' "${CYAN}Threads (default 1): ${RESET}"
  IFS= read -r threads
  [[ -n "$threads" ]] && pig_args+=("-t" "$threads")

  printf '%b' "${CYAN}Show ARP who-has? [y/N]: ${RESET}"
  IFS= read -r arp_mon
  [[ "${arp_mon,,}" == "y" ]] && pig_args+=("-a")

  printf '%b' "${CYAN}Show ICMP requests? [y/N]: ${RESET}"
  IFS= read -r icmp_mon
  [[ "${icmp_mon,,}" == "y" ]] && pig_args+=("-i")

  printf '%b' "${CYAN}Show lease options? [y/N]: ${RESET}"
  IFS= read -r show_opts
  [[ "${show_opts,,}" == "y" ]] && pig_args+=("-o")

  printf '%b' "${CYAN}Show lease confirmations? [y/N]: ${RESET}"
  IFS= read -r show_lease
  [[ "${show_lease,,}" == "y" ]] && pig_args+=("-l")

  printf '%b' "${CYAN}Gratuitous ARP neighbor attack? [y/N]: ${RESET}"
  IFS= read -r gar
  [[ "${gar,,}" == "y" ]] && pig_args+=("-g")

  printf '%b' "${CYAN}Release all neighbor IPs? [y/N]: ${RESET}"
  IFS= read -r rel
  [[ "${rel,,}" == "y" ]] && pig_args+=("-r")

  printf '%b' "${CYAN}ARP neighbor scan? [y/N]: ${RESET}"
  IFS= read -r arpscan
  [[ "${arpscan,,}" == "y" ]] && pig_args+=("-n")

  printf '%b' "${CYAN}Thread spawn timeout (default 0.4): ${RESET}"
  IFS= read -r t_spawn
  [[ -n "$t_spawn" ]] && pig_args+=("-x" "$t_spawn")

  printf '%b' "${CYan}DOS timeout (default 8): ${RESET}"
  IFS= read -r t_dos
  [[ -n "$t_dos" ]] && pig_args+=("-y" "$t_dos")

  printf '%b' "${CYAN}DHCP request timeout (default 2): ${RESET}"
  IFS= read -r t_dhcp
  [[ -n "$t_dhcp" ]] && pig_args+=("-z" "$t_dhcp")

  printf '%b' "${CYAN}Colored output? [y/N]: ${RESET}"
  IFS= read -r col
  [[ "${col,,}" == "y" ]] && pig_args+=("-c")

  # Final review
  while true; do
    clear_screen
    logo
    banner "Final DHCP Command"
    printf '%b\n' "${YELLOW}Current arguments:${RESET}"
    printf '  %s\n' "${pig_args[*]:-(none)}"
    printf '\n%b' "${CYAN}[E]dit manually, [R]un, [A]bort: ${RESET}"
    IFS= read -r final
    case "${final,,}" in
      e|edit)
        printf '%b' "${CYAN}Enter replacement arguments: ${RESET}"
        IFS= read -r new_args
        [[ -n "$new_args" ]] && pig_args=($new_args)
        ;;
      r|run)
        run_pig "${pig_args[@]}"
        return
        ;;
      a|abort)
        printf '%b\n' "${MUTED}Wizard cancelled.${RESET}"
        pause
        return
        ;;
      *) printf '%b\n' "${RED}Invalid choice.${RESET}"; sleep 1 ;;
    esac
  done
}

quick_dhcp_attacks_menu() {
  while true; do
    clear_screen
    logo
    banner "Quick DHCP Attack Profiles"
    cat <<'QUICKMENU'
  [1] Basic exhaustion
  [2] Verbose exhaustion (v99)
  [3] Exhaustion + gratuitous ARP
  [4] Exhaustion + release neighbour IPs
  [5] Custom MAC list
  [6] DHCPv6 exhaustion
  [7] Fuzz mode
  [8] Multi-threaded (8 threads) + verbose
  [0] Back
QUICKMENU
    printf '\n%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r choice
    case $choice in
      1) run_pig ;;
      2) run_pig -v 99 ;;
      3) run_pig -g ;;
      4) run_pig -r ;;
      5)
        printf '%b' "${CYAN}Enter MACs (comma separated): ${RESET}"
        IFS= read -r macs
        [[ -z "$macs" ]] && { printf '%b\n' "${RED}No MACs provided.${RESET}"; sleep 1; continue; }
        run_pig -s "$macs"
        ;;
      6) run_pig -6 ;;
      7) run_pig -f ;;
      8) run_pig -t 8 -v 99 ;;
      0) break ;;
      *) printf '%b\n' "${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

dhcp_attack_menu() {
  while true; do
    clear_screen
    logo
    banner "DHCP Attack Lab"
    cat <<'DHCPMENU'
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw pig.py arguments
  [0] Return to main menu
DHCPMENU
    printf '\n%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r choice
    case $choice in
      1) quick_dhcp_attacks_menu ;;
      2) advanced_pig_wizard ;;
      3)
        printf '%b' "${CYAN}Enter raw arguments: ${RESET}"
        IFS= read -r raw_args
        if [[ -z "$raw_args" ]]; then
          printf '%b\n' "${RED}No arguments.${RESET}"
          sleep 1; continue
        fi
        eval "raw_args_array=($raw_args)"
        run_pig "${raw_args_array[@]}"
        ;;
      0) break ;;
      *) printf '%b\n' "${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

# ==================== DNS ATTACK LAB (new) ===================================

run_dnsforge() {
  local args=("$@")
  local iface=""
  local mode=""
  local cmd=()

  # Separate positional mode (respond/relay) from other args
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "respond" || "${args[$i]}" == "relay" ]]; then
      mode="${args[$i]}"
      unset 'args[$i]'
      args=("${args[@]}")   # re-index
      break
    fi
  done

  # Extract interface if already in args
  for ((i=0; i<${#args[@]}; i++)); do
    if [[ "${args[$i]}" == "-i" || "${args[$i]}" == "--interface" ]]; then
      iface="${args[$i+1]}"
      break
    fi
  done

  if [[ -z "$iface" ]]; then
    iface=$(get_interface) || { printf '%b\n' "${RED}No interface given, aborting.${RESET}"; sleep 1; return 1; }
    cmd+=("-i" "$iface")
  else
    SAVED_IFACE="$iface"
  fi

  # Mode must be supplied
  if [[ -z "$mode" ]]; then
    printf '%b\n' "${YELLOW}Select mode:${RESET}"
    printf '  [r] respond (intercept request)\n'
    printf '  [l] relay (intercept response)\n'
    printf '%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r m
    case "$m" in
      r|respond) mode="respond" ;;
      l|relay)   mode="relay" ;;
      *)
        printf '%b\n' "${RED}Invalid mode, aborting.${RESET}"
        sleep 1
        return 1
        ;;
    esac
  fi

  # Build final command: python3 -m DNS.dnsforge [options] mode
  # We must run from SCRIPT_DIR so the module is found
  local full_cmd=(python3 -m "$DNSFORGE_MODULE" "${args[@]}" "${cmd[@]}" "$mode")
  local desc="${full_cmd[*]}"

  clear_screen
  logo
  banner "Execute DNS Attack"
  printf '\n%bCommand:%b\n  %s\n' "$YELLOW" "$RESET" "$desc"
  printf '%b\n' "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  if ! confirm_attack "$desc"; then
    printf '%b\n' "${MUTED}Attack cancelled.${RESET}"
    pause
    return 0
  fi

  printf '\n%b\n' "${CYAN}Launching attack... (Press Ctrl+C to stop)${RESET}"
  cd "$SCRIPT_DIR" || exit 1
  if [[ $EUID -ne 0 ]]; then
    sudo "${full_cmd[@]}"
  else
    "${full_cmd[@]}"
  fi
  cd - >/dev/null
  printf '\n%b\n' "${GREEN}Attack finished.${RESET}"
  pause
}

advanced_dns_wizard() {
  local dns_args=()
  local mode=""

  clear_screen
  logo
  banner "Advanced DNS Attack Configuration"
  printf '%b\n' "${MUTED}Configure each option. Leave empty to skip.${RESET}\n"

  # Mode (positional)
  printf '%b' "${CYAN}Mode: [r] respond / [l] relay: ${RESET}"
  IFS= read -r m
  case "$m" in
    r|respond) mode="respond" ;;
    l|relay)   mode="relay" ;;
    *)
      printf '%b\n' "${RED}Invalid mode, defaulting to respond.${RESET}"
      mode="respond"
      ;;
  esac

  # Poison IP (mandatory)
  printf '%b' "${CYAN}Poison IP (e.g. 192.168.1.100): ${RESET}"
  IFS= read -r poison_ip
  [[ -n "$poison_ip" ]] && dns_args+=("-p" "$poison_ip") || {
    printf '%b\n' "${RED}Poison IP is required. Aborting.${RESET}"
    pause
    return
  }

  # Query name(s)
  printf '%b' "${CYAN}DNS query name(s) (comma separated, e.g. google.com,yahoo.com): ${RESET}"
  IFS= read -r query_names
  [[ -n "$query_names" ]] && dns_args+=("-q" "$query_names")

  # TTL
  printf '%b' "${CYAN}TTL in seconds (default probably 60): ${RESET}"
  IFS= read -r ttl
  [[ -n "$ttl" ]] && dns_args+=("-ttl" "$ttl")

  # Stealth mode
  printf '%b' "${CYAN}Enable stealth mode? [y/N]: ${RESET}"
  IFS= read -r stealth
  if [[ "${stealth,,}" == "y" ]]; then
    dns_args+=("-s")
    printf '%b' "${CYAN}  Authoritative DNS server IP: ${RESET}"
    IFS= read -r dns_server
    [[ -n "$dns_server" ]] && dns_args+=("-ds" "$dns_server")
    printf '%b' "${CYAN}  Victim domain: ${RESET}"
    IFS= read -r domain
    [[ -n "$domain" ]] && dns_args+=("-d" "$domain")
  fi

  # ARP spoofing target(s)
  printf '%b' "${CYAN}ARP spoofing target IP (or leave empty to skip): ${RESET}"
  IFS= read -r target_ip
  if [[ -n "$target_ip" ]]; then
    dns_args+=("-t" "$target_ip")
  else
    printf '%b' "${CYAN}Use target file instead? [y/N]: ${RESET}"
    IFS= read -r use_file
    if [[ "${use_file,,}" == "y" ]]; then
      printf '%b' "${CYAN}Path to target file: ${RESET}"
      IFS= read -r target_file
      [[ -n "$target_file" ]] && dns_args+=("-tf" "$target_file")
    fi
  fi

  # Turn off ARP spoofing explicitly?
  printf '%b' "${CYAN}Disable ARP spoofing completely? [y/N]: ${RESET}"
  IFS= read -r no_arp
  [[ "${no_arp,,}" == "y" ]] && dns_args+=("--no-arp-spoof")

  # Verbose
  printf '%b' "${CYAN}Verbose output? [y/N]: ${RESET}"
  IFS= read -r verbose
  [[ "${verbose,,}" == "y" ]] && dns_args+=("-v")

  # Final review (same pattern as DHCP wizard)
  while true; do
    clear_screen
    logo
    banner "Final DNS Command"
    printf '%b\n' "${YELLOW}Arguments:${RESET}"
    printf '  %s\n' "${dns_args[*]} ${mode}"
    printf '\n%b' "${CYAN}[E]dit manually, [R]un, [A]bort: ${RESET}"
    IFS= read -r final
    case "${final,,}" in
      e|edit)
        printf '%b' "${CYAN}Enter replacement arguments (without mode): ${RESET}"
        IFS= read -r new_args
        if [[ -n "$new_args" ]]; then
          dns_args=($new_args)
        fi
        ;;
      r|run)
        run_dnsforge "${dns_args[@]}" "$mode"
        return
        ;;
      a|abort)
        printf '%b\n' "${MUTED}Wizard cancelled.${RESET}"
        pause
        return
        ;;
      *) printf '%b\n' "${RED}Invalid choice.${RESET}"; sleep 1 ;;
    esac
  done
}

quick_dns_attacks_menu() {
  while true; do
    clear_screen
    logo
    banner "Quick DNS Attack Profiles"
    cat <<'DNSQUICK'
  [1] Basic respond (poison all queries)
  [2] Basic relay (poison responses)
  [3] Stealth respond (custom domain + authoritative server)
  [4] Respond with ARP spoofing target
  [5] Respond, no ARP spoofing
  [0] Back
DNSQUICK
    printf '\n%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r choice

    # For quick attacks we need a few inputs (poison IP, maybe query)
    # We'll ask interactively inside each case
    case $choice in
      1)
        printf '%b' "${CYAN}Poison IP: ${RESET}"; IFS= read -r pip
        [[ -z "$pip" ]] && { printf '%b\n' "${RED}Required.${RESET}"; sleep 1; continue; }
        run_dnsforge -p "$pip" respond
        ;;
      2)
        printf '%b' "${CYAN}Poison IP: ${RESET}"; IFS= read -r pip
        [[ -z "$pip" ]] && { printf '%b\n' "${RED}Required.${RESET}"; sleep 1; continue; }
        run_dnsforge -p "$pip" relay
        ;;
      3)
        printf '%b' "${CYAN}Poison IP: ${RESET}"; IFS= read -r pip
        printf '%b' "${CYAN}Authoritative DNS server IP: ${RESET}"; IFS= read -r dns_srv
        printf '%b' "${CYAN}Victim domain: ${RESET}"; IFS= read -r vdomain
        if [[ -z "$pip" || -z "$dns_srv" || -z "$vdomain" ]]; then
          printf '%b\n' "${RED}All fields required.${RESET}"; sleep 1; continue
        fi
        run_dnsforge -p "$pip" -s -ds "$dns_srv" -d "$vdomain" respond
        ;;
      4)
        printf '%b' "${CYAN}Poison IP: ${RESET}"; IFS= read -r pip
        printf '%b' "${CYAN}Target IP for ARP spoofing: ${RESET}"; IFS= read -r tgt
        [[ -z "$pip" || -z "$tgt" ]] && { printf '%b\n' "${RED}Both required.${RESET}"; sleep 1; continue; }
        run_dnsforge -p "$pip" -t "$tgt" respond
        ;;
      5)
        printf '%b' "${CYAN}Poison IP: ${RESET}"; IFS= read -r pip
        [[ -z "$pip" ]] && { printf '%b\n' "${RED}Required.${RESET}"; sleep 1; continue; }
        run_dnsforge -p "$pip" --no-arp-spoof respond
        ;;
      0) break ;;
      *) printf '%b\n' "${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

dns_attack_menu() {
  while true; do
    clear_screen
    logo
    banner "DNS Attack Lab (dnsforge)"
    cat <<'DNSMENU'
  [1] Quick Attack (presets)
  [2] Advanced Configuration (wizard)
  [3] Enter raw dnsforge arguments
  [0] Return to main menu
DNSMENU
    printf '\n%b' "${CYAN}Choice: ${RESET}"
    IFS= read -r choice
    case $choice in
      1) quick_dns_attacks_menu ;;
      2) advanced_dns_wizard ;;
      3)
        printf '%b' "${CYAN}Enter raw arguments (including mode at end): ${RESET}"
        IFS= read -r raw_args
        if [[ -z "$raw_args" ]]; then
          printf '%b\n' "${RED}No arguments.${RESET}"
          sleep 1; continue
        fi
        eval "raw_args_array=($raw_args)"
        run_dnsforge "${raw_args_array[@]}"
        ;;
      0) break ;;
      *) printf '%b\n' "${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

# --- Help / version ----------------------------------------------------------
print_help() {
  cat <<HELP
${BOLD}Project Nemesis v${VERSION}${RESET}
A safe, educational network-security dashboard with DHCP and DNS attack labs.

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
  7 / attack / dhcplab   DHCP attack lab
  8 / dnsattack          DNS attack lab
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
    dnsattack|8)  dns_attack_menu;;
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
  [2] DNS Attack Lab
  [0] Exit
MENU
    printf '%b' "${RESET}"
    printf '\n%b' "${CYAN}Select a module: ${RESET}"
    IFS= read -r choice || choice=0
    case $choice in
      1) dhcp_attack_menu ;;
      2) dns_attack_menu ;;
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