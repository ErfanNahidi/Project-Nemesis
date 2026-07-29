#!/usr/bin/env bash
# ----------------------------------------------------------------------
# Project Nemesis – Unified Dashboard (with fixed launcher)
# ----------------------------------------------------------------------

set -euo pipefail

VERSION="0.1.0"

# ---- get the real path of this script (even if run via symlink) ----
if command -v realpath &>/dev/null; then
    SCRIPT_REALPATH="$(realpath "$0")"
elif command -v readlink &>/dev/null; then
    SCRIPT_REALPATH="$(readlink -f "$0")"
else
    # Fallback: expand to absolute path manually
    SCRIPT_REALPATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
fi
SCRIPT_DIR="$(dirname "$SCRIPT_REALPATH")"

# ----------------------------------------------------------------------
# Terminal colours (real escape codes)
# ----------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED=$'\033[1;31m'
    MUTED=$'\033[0;31m'
    CYAN=$'\033[1;36m'
    YELLOW=$'\033[1;33m'
    GREEN=$'\033[1;32m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
    HLINE='─'
    VLINE='│'
    TOPL='┌'
    TOPR='┐'
    BOTL='└'
    BOTR='┘'
else
    RED='' MUTED='' CYAN='' YELLOW='' GREEN='' BOLD='' RESET=''
    HLINE='-'
    VLINE='|'
    TOPL='+'
    TOPR='+'
    BOTL='+'
    BOTR='+'
fi

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
clear_screen() {
    if command -v clear &>/dev/null; then
        clear
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        cls 2>/dev/null || printf '\033[2J\033[H'
    else
        printf '\033[2J\033[H'
    fi
}

banner() {
    local text="$1" width=60 pad line
    pad=$(( (width - 2 - ${#text}) / 2 ))
    printf -v line '%*s' $((width - 2)) ''
    line="${line// /$HLINE}"
    local top="${RED}${TOPL}${line}${TOPR}${RESET}"
    local middle="${RED}${VLINE}${RESET}$(printf '%*s' $pad '')${BOLD}${text}${RESET}$(printf '%*s' $((width - 2 - ${#text} - pad)) '')${RED}${VLINE}${RESET}"
    local bottom="${RED}${BOTL}${line}${BOTR}${RESET}"
    echo -e "$top"
    echo -e "$middle"
    echo -e "$bottom"
}

logo() {
    clear_screen
    echo -e "${RED}"
    cat << 'EOF'
███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
EOF
    echo -e "${RESET}"
    echo -e "${MUTED}               Windows Services Security Pentest Project${RESET}\n"
}

pause() {
    read -rp $'\n'"${MUTED}Press Enter to return...${RESET}"
}

# ----------------------------------------------------------------------
# Cloning helper (for Scanner / DHCP Havoc)
# ----------------------------------------------------------------------
safe_clone() {
    local repo_url="$1"
    local repo_name="$(basename "$repo_url" .git)"
    clear_screen
    logo
    banner "Clone Repository"
    echo -e "${CYAN}Repository: ${repo_url}${RESET}"
    echo -e "${CYAN}Target: $(pwd)/${repo_name}${RESET}"
    if [[ -d "$repo_name" ]]; then
        echo -e "\n${YELLOW}Directory '${repo_name}' already exists.${RESET}"
        read -rp "Overwrite? (yes/no): " ans
        [[ "${ans,,}" =~ ^(y|yes)$ ]] || { echo -e "${MUTED}Clone skipped.${RESET}"; pause; return; }
        rm -rf "$repo_name" || { echo -e "${RED}Failed to remove.${RESET}"; pause; return; }
    fi
    echo -e "${CYAN}Cloning...${RESET}"
    if git clone "$repo_url"; then
        echo -e "${GREEN}Clone successful.${RESET}"
    else
        echo -e "${RED}Clone failed.${RESET}"
    fi
    pause
}

# ----------------------------------------------------------------------
# LAUNCHER MANAGEMENT (INSTALL / REMOVE / UPDATE)
# ----------------------------------------------------------------------
LAUNCHER_PATH="/usr/local/bin/nemesis"
OFFICIAL_REMOTE="https://github.com/ErfanNahidi/Project-Nemesis"

launcher_install() {
    clear_screen
    logo
    banner "Install Nemesis Launcher"

    # 1. Ensure THIS script is executable
    if [[ ! -x "$SCRIPT_REALPATH" ]]; then
        echo -e "${YELLOW}Making this script executable...${RESET}"
        chmod +x "$SCRIPT_REALPATH" || {
            echo -e "${RED}Failed to set execute permission on $SCRIPT_REALPATH.${RESET}"
            pause
            return
        }
    fi

    # 2. Check if a launcher already exists
    if [[ -e "$LAUNCHER_PATH" ]] || [[ -L "$LAUNCHER_PATH" ]]; then
        # Check if the existing symlink points to a non-executable target
        if [[ -L "$LAUNCHER_PATH" ]]; then
            local target
            target=$(readlink -f "$LAUNCHER_PATH" 2>/dev/null || readlink "$LAUNCHER_PATH")
            if [[ ! -x "$target" ]]; then
                echo -e "${YELLOW}Existing symlink points to a non-executable file.${RESET}"
                echo -e "I will make it executable and keep the symlink."
                chmod +x "$target" 2>/dev/null && {
                    echo -e "${GREEN}Fixed. 'nemesis' should now work.${RESET}"
                    pause
                    return
                } || echo -e "${RED}Failed to fix permissions.${RESET}"
            else
                echo -e "${YELLOW}A working nemesis command already exists.${RESET}"
                read -rp "Overwrite? (yes/no): " ans
                [[ "${ans,,}" =~ ^(y|yes)$ ]] || { echo -e "${MUTED}Installation cancelled.${RESET}"; pause; return; }
                sudo rm -f "$LAUNCHER_PATH"
            fi
        else
            # It's a regular file, not a symlink – ask to replace
            echo -e "${YELLOW}A file (not a symlink) exists at ${LAUNCHER_PATH}${RESET}"
            read -rp "Overwrite? (yes/no): " ans
            [[ "${ans,,}" =~ ^(y|yes)$ ]] || { echo -e "${MUTED}Installation cancelled.${RESET}"; pause; return; }
            sudo rm -f "$LAUNCHER_PATH"
        fi
    fi

    # 3. Create fresh symlink
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
    banner "Update Nemesis"

    if [[ ! -d "$SCRIPT_DIR/.git" ]]; then
        echo -e "${YELLOW}Current directory is not a Git repository.${RESET}"
        echo -e "To update, clone the official repo and re-run:"
        echo -e "  git clone ${OFFICIAL_REMOTE}"
        pause
        return
    fi

    # Check remote origin
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
            current_remote="$OFFICIAL_REMOTE"
        else
            echo -e "${MUTED}Update cancelled.${RESET}"
            pause
            return
        fi
    fi

    echo -e "${CYAN}Pulling latest changes from ${OFFICIAL_REMOTE}...${RESET}"
    if git -C "$SCRIPT_DIR" pull; then
        echo -e "${GREEN}Update successful.${RESET}"
    else
        echo -e "${RED}Update failed. Check network or repository state.${RESET}"
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
  [3] Update    – pull latest from official GitHub repo
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

# ----------------------------------------------------------------------
# About menus
# ----------------------------------------------------------------------
ABOUT_ME="I'm Erfan Nahidi
Virtualization & Infrastructure Administrator

Focused on designing scalable, resilient, and high-performance datacenter
infrastructures. Passionate about virtualization, Linux systems, networking,
and low-level computing, with a strong interest in systems programming and
infrastructure engineering."

ABOUT_PROJECT="This project was developed as part of my Software Project course at
Islamic Azad University, Karaj.

It is provided strictly for educational and research purposes and is intended
to be used only in isolated virtual lab environments.

This software is not designed, tested, or intended for use against production
systems or unauthorized targets. The author assumes no responsibility for any
misuse or damages resulting from the use of this project."

about_me() {
    clear_screen
    logo
    banner "About Me"
    echo -e "${CYAN}${ABOUT_ME}${RESET}"
    pause
}

about_project() {
    clear_screen
    logo
    banner "About This Project"
    echo -e "${YELLOW}${ABOUT_PROJECT}${RESET}"
    pause
}

about_menu() {
    while true; do
        clear_screen
        logo
        banner "About Menu"
        echo -e "${YELLOW}
  [1] About Me
  [2] About this Project
  [0] Return to main menu
${RESET}"
        read -rp $'\n'"${CYAN}Choice: ${RESET}" choice
        case "$choice" in
            1) about_me ;;
            2) about_project ;;
            0) break ;;
            *) echo -e "${RED}Invalid option.${RESET}" && sleep 1 ;;
        esac
    done
}

# ----------------------------------------------------------------------
# Main Dashboard
# ----------------------------------------------------------------------
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
  [2] Scanner
  [3] DHCP Havoc
  [9] About
  [0] Exit
${RESET}"
        read -rp $'\n'"${CYAN}Select a module: ${RESET}" choice
        case "$choice" in
            0|q|Q|exit)
                clear_screen
                echo -e "${MUTED}Stay curious. Stay authorized.${RESET}"
                exit 0 ;;
            1) launcher_menu ;;
            2) safe_clone "https://github.com/ErfanNahidi/Nemesis-Scanner" ;;
            3) safe_clone "https://github.com/ErfanNahidi/Nemesis-DHCP-Havoc" ;;
            9) about_menu ;;
            *) echo -e "${RED}Please select a listed option.${RESET}" && sleep 1 ;;
        esac
    done
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi