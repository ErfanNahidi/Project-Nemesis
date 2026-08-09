#!/usr/bin/env bash
# scripts/about.sh – About menus
set -euo pipefail

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