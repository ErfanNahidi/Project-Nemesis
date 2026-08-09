#!/usr/bin/env bash
# ----------------------------------------------------------------------
# Project Nemesis – Dashboard (modular edition)
# ----------------------------------------------------------------------
set -euo pipefail

VERSION="0.2.0"

# ---- real path of this script (works through symlinks) ----
if command -v realpath &>/dev/null; then
    SCRIPT_REALPATH="$(realpath "$0")"
elif command -v readlink &>/dev/null; then
    SCRIPT_REALPATH="$(readlink -f "$0")"
else
    SCRIPT_REALPATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
fi
SCRIPT_DIR="$(dirname "$SCRIPT_REALPATH")"

# ---- source shared helpers ----
if [[ -f "$SCRIPT_DIR/utils/helpers.sh" ]]; then
    source "$SCRIPT_DIR/utils/helpers.sh"
else
    echo "ERROR: utils/helpers.sh not found." >&2
    exit 1
fi

# ---- set modules directory for tool_handler ----
MODULES_DIR="$SCRIPT_DIR/modules"

# ---- source sub-menus ----
source "$SCRIPT_DIR/scripts/launcher_core.sh"
source "$SCRIPT_DIR/scripts/launcher_update.sh"
source "$SCRIPT_DIR/scripts/general.sh"
source "$SCRIPT_DIR/scripts/cve.sh"
source "$SCRIPT_DIR/scripts/about.sh"
# ---- main dashboard ----
main() {
    case "${1:-}" in
        --version) echo "Project Nemesis v$VERSION"; exit 0 ;;
        --check)
            command -v git &>/dev/null || { echo "git is required."; exit 1; }
            echo -e "${GREEN}✓ All tools verified.${RESET}"
            exit 0 ;;
        "") ;;
        *) echo "Unknown argument." >&2; exit 1 ;;
    esac

    if ! command -v git &>/dev/null; then
        echo -e "${RED}ERROR: git is not installed.${RESET}" >&2
        exit 1
    fi

    while true; do
        clear_screen
        logo
        banner "Security Learning Dashboard"
        echo -e "${YELLOW}
  [1] Nemesis Launcher (install/update/remove)
  [2] General Attacks
  [3] CVE Exploits
  [4] About
  [0] Exit
${RESET}"
        read -rp $'\n'"${CYAN}Select an option: ${RESET}" choice
        case "$choice" in
            1) launcher_menu ;;
            2) general_attack_menu ;;
            3) cve_attack_menu ;;
            4) about_menu ;;
            0|q|Q|exit)
                clear_screen
                echo -e "${MUTED}Stay curious. Stay authorized.${RESET}"
                exit 0 ;;
            *) echo -e "${RED}Please select a listed option.${RESET}" && sleep 1 ;;
        esac
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi