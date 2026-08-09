#!/usr/bin/env bash
# utils/helpers.sh – shared functions for Project Nemesis
set -euo pipefail

# ---- Terminal colours ----
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

# ---- Utility functions ----
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

# ---- Tool management ----
MODULES_DIR=""   # will be set by the main script

install_deps() {
    local dir="$1"
    local req="$dir/requirements.txt"
    if [[ -f "$req" ]]; then
        echo -e "${CYAN}Installing Python dependencies from $req...${RESET}"
        if command -v pip3 &>/dev/null; then
            pip3 install -r "$req" || echo -e "${RED}Failed to install dependencies.${RESET}"
        elif command -v pip &>/dev/null; then
            pip install -r "$req" || echo -e "${RED}Failed to install dependencies.${RESET}"
        else
            echo -e "${RED}pip not found. Please install dependencies manually.${RESET}"
        fi
    fi
}

run_tool() {
    local tool_dir="$1"
    local cli_path="${tool_dir}/cli.py"

    if [[ ! -f "$cli_path" ]]; then
        echo -e "${RED}No 'cli.py' found in ${tool_dir}.${RESET}"
        echo "Cannot launch the tool."
        pause
        return 1
    fi

    clear_screen
    logo
    banner "Running $(basename "$tool_dir")"
    echo -e "${MUTED}Press Ctrl+C to stop and return to the dashboard.${RESET}\n"

    install_deps "$tool_dir"
    sudo python3 "$cli_path" || echo -e "\n${RED}The tool exited with an error.${RESET}"
    pause
}

tool_handler() {
    local repo_url="$1"
    local repo_name="$(basename "$repo_url" .git)"

    # Ensure we operate inside MODULES_DIR
    mkdir -p "$MODULES_DIR"
    cd "$MODULES_DIR"

    while true; do
        clear_screen
        logo
        banner "${repo_name}"

        if [[ -d "$repo_name" ]]; then
            echo -e "${GREEN}Tool directory found: ${MODULES_DIR}/${repo_name}${RESET}"
            echo
            echo -e "${YELLOW}  [1] Run tool${RESET}"
            echo -e "${YELLOW}  [2] Reclone (update)${RESET}"
            echo -e "${YELLOW}  [0] Back to menu${RESET}"
            read -rp $'\n'"${CYAN}Choice: ${RESET}" choice
            case "$choice" in
                1) run_tool "$repo_name" ;;
                2)
                    echo -e "${RED}This will delete '${repo_name}' and re-clone.${RESET}"
                    read -rp "Proceed? (yes/no): " ans
                    if [[ "${ans,,}" =~ ^(y|yes)$ ]]; then
                        rm -rf "$repo_name"
                        echo -e "${CYAN}Re-cloning ${repo_url}...${RESET}"
                        if git clone "$repo_url"; then
                            echo -e "${GREEN}Clone successful.${RESET}"
                            install_deps "$repo_name"
                            read -rp "Run it now? (yes/no): " run_ans
                            [[ "${run_ans,,}" =~ ^(y|yes)$ ]] && run_tool "$repo_name"
                        else
                            echo -e "${RED}Clone failed.${RESET}"
                        fi
                    else
                        echo -e "${MUTED}Reclone cancelled.${RESET}"
                    fi
                    ;;
                0) cd - >/dev/null; break ;;
                *) echo -e "${RED}Invalid option.${RESET}" && sleep 1 ;;
            esac
        else
            echo -e "${YELLOW}Tool not found locally.${RESET}"
            echo -e "${CYAN}Cloning from ${repo_url}...${RESET}"
            if git clone "$repo_url"; then
                echo -e "${GREEN}Clone successful.${RESET}"
                install_deps "$repo_name"
                read -rp "Run it now? (yes/no): " run_ans
                [[ "${run_ans,,}" =~ ^(y|yes)$ ]] && run_tool "$repo_name"
            else
                echo -e "${RED}Clone failed.${RESET}"
            fi
            cd - >/dev/null
            break
        fi
    done
    cd - >/dev/null
}