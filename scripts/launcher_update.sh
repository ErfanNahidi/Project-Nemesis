#!/usr/bin/env bash
# scripts/launcher_update.sh – Update logic & launcher menu
set -euo pipefail

LAUNCHER_PATH="/usr/local/bin/nemesis"
OFFICIAL_REMOTE="https://github.com/ErfanNahidi/Project-Nemesis"

launcher_update() {
    clear_screen
    logo
    banner "Update Nemesis Dashboard"

    if [[ ! -d "$SCRIPT_DIR/.git" ]]; then
        echo -e "${YELLOW}Current directory is not a Git repository.${RESET}"
        echo -e "To update, clone the official repo and re-run:"
        echo -e "  git clone ${OFFICIAL_REMOTE}"
        pause
        return
    fi

    local current_remote
    current_remote=$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || true)

    if [[ "$current_remote" != "$OFFICIAL_REMOTE" ]]; then
        echo -e "${YELLOW}Your remote is currently:${RESET}"
        echo -e "  ${current_remote:-none}"
        echo -e "${YELLOW}The official repository is:${RESET}"
        echo -e "  ${OFFICIAL_REMOTE}"
        echo
        read -rp "Change remote to official and pull? (yes/no): " ans
        if [[ "${ans,,}" =~ ^(y|yes)$ ]]; then
            echo -e "${CYAN}Updating remote...${RESET}"
            git -C "$SCRIPT_DIR" remote set-url origin "$OFFICIAL_REMOTE"
        else
            echo -e "${MUTED}Update cancelled.${RESET}"
            pause
            return
        fi
    fi

    echo -e "${CYAN}Pulling latest dashboard code...${RESET}"
    if git -C "$SCRIPT_DIR" pull; then
        echo -e "${GREEN}Dashboard updated successfully.${RESET}"
    else
        echo -e "${RED}Pull failed. Check your network or repository state.${RESET}"
    fi
    pause
}

launcher_menu() {
    while true; do
        clear_screen
        logo
        banner "Nemesis Launcher"
        echo -e "${YELLOW}
  [1] Install   – make 'nemesis' available system-wide
  [2] Remove    – remove 'nemesis' command
  [3] Update    – pull latest dashboard from GitHub
  [0] Back to main menu
${RESET}"
        read -rp $'\n'"${CYAN}Choice: ${RESET}" choice
        case "$choice" in
            1) launcher_install ;;
            2) launcher_remove ;;
            3) launcher_update ;;
            0) break ;;
            *) echo -e "${RED}Invalid option.${RESET}" && sleep 1 ;;
        esac
    done
}