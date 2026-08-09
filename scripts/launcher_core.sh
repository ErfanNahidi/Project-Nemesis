#!/usr/bin/env bash
# scripts/launcher_core.sh – Install / Remove logic
set -euo pipefail

LAUNCHER_PATH="/usr/local/bin/nemesis"

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