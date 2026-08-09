#!/usr/bin/env bash
# scripts/general.sh – General Attacks menu
set -euo pipefail

general_attack_menu() {
    while true; do
        clear_screen
        logo
        banner "General Attacks"
        echo -e "${YELLOW}
  [1] Scanner
  [2] DHCP
  [3] DoS
  [4] Sniffer
  [5] AD Reaper
  [6] SMB Phantom
  [7] DNS
  [8] RCP (Empty)
  [0] Back to main menu
${RESET}"
        read -rp $'\n'"${CYAN}Select a module: ${RESET}" choice
        case "$choice" in
            1) tool_handler "https://github.com/ErfanNahidi/Nemesis-Scanner" ;;
            2) tool_handler "https://github.com/ErfanNahidi/Nemesis-DHCP-Havoc" ;;
            3) tool_handler "https://github.com/ErfanNahidi/Nemesis-DoS-Engine" ;;
            4) tool_handler "https://github.com/ErfanNahidi/Nemesis-Sniffiner" ;;
            5) tool_handler "https://github.com/ErfanNahidi/Nemesis-AD-Reaper" ;;
            6) tool_handler "https://github.com/ErfanNahidi/Nemesis-SMB-Phantom" ;;
            7) tool_handler "https://github.com/ErfanNahidi/Nemesis-DNS-Hydra" ;;
            8) tool_handler "" ;;   # RCP placeholder
            0) break ;;
            *) echo -e "${RED}Please select a listed option.${RESET}" && sleep 1 ;;
        esac
    done
}