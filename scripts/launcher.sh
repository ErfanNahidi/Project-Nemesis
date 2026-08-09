#!/usr/bin/env bash
# scripts/launcher.sh – Launcher management
set -euo pipefail

LAUNCHER_PATH="/usr/local/bin/nemesis"
OFFICIAL_REMOTE="https://github.com/ErfanNahidi/Project-Nemesis"

launcher_install() {
    clear_screen
    logo
    banner "Install Nemesis Launcher"

    if [[ ! -x "$SCRIPT_REALPATH" ]]; then
        echo -e "${YELLOW}Making this script executable...${RESET}"
        chmod +x "$SCRIPT_REALPATH" || {
            echo -e "${RED}Failed to set execute permission.${RESET}"
            pause
            return
        }
    fi

    if [[ -e "$LAUNCHER_PATH" ]] || [[ -L "$LAUNCHER_PATH" ]]; then
        if [[ -L "$LAUNCHER_PATH" ]]; then
            local target
            target=$(readlink -f "$LAUNCHER_PATH" 2>/dev/null || readlink "$LAUNCHER_PATH")
            if [[ ! -x "$target" ]]; then
                echo -e "${YELLOW}Existing symlink points to non‑executable file. Fixing...${RESET}"
                chmod +x "$target" 2>/dev/null && {
                    echo -e "${GREEN}Fixed. 'nemesis' should now work.${RESET}"
                    pause
                    return
                }
            else
                echo -e "${YELLOW}A working nemesis command already exists.${RESET}"
                read -rp "Overwrite? (yes/no): " ans
                [[ "${ans,,}" =~ ^(y|yes)$ ]] || { echo -e "${MUTED}Installation cancelled.${RESET}"; pause; return; }
                sudo rm -f "$LAUNCHER_PATH"
            fi
        else
            echo -e "${YELLOW}A file (not a symlink) exists at ${LAUNCHER_PATH}${RESET}"
            read -rp "Overwrite? (yes/no): " ans
            [[ "${ans,,}" =~ ^(y|yes)$ ]] || { echo -e "${MUTED}Installation cancelled.${RESET}"; pause; return; }
            sudo rm -f "$LAUNCHER_PATH"
        fi
    fi

    echo -e "${CYAN}Creating symlink to: ${SCRIPT_REALPATH}${RESET}"
    if sudo ln -s "$SCRIPT_REALPATH" "$LAUNCHER_PATH"; then
        echo -e "${GREEN}Installation successful!${RESET}"
        echo -e "Now you can simply type ${BOLD}nemesis${RESET} in your terminal."
    else
        echo -e "${RED}Failed to create symlink.${RESET}"
    fi
    pause
}

launcher_remove() {
    clear_screen
    logo
    banner "Remove Nemesis Launcher"
    if [[ ! -e "$LAUNCHER_PATH" ]]; then
        echo -e "${YELLOW}Nemesis is not installed.${RESET}"
        pause
        return
    fi
    echo -e "${RED}This will remove the 'nemesis' command.${RESET}"
    read -rp "Are you sure? (yes/no): " ans
    [[ "${ans,,}" =~ ^(y|yes)$ ]] || { echo -e "${MUTED}Removal cancelled.${RESET}"; pause; return; }
    if sudo rm -f "$LAUNCHER_PATH"; then
        echo -e "${GREEN}Nemesis launcher removed.${RESET}"
    else
        echo -e "${RED}Failed to remove.${RESET}"
    fi
    pause
}

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