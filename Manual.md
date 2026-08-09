# Project Nemesis – User Manual

> **Version:** 0.2.0  
> **Project:** Windows Services Security Pentest Framework  
> **Author:** Erfan Nahidi  
> **License:** MIT

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Installation & Setup](#2-installation--setup)
   - [Clone the Repository](#clone-the-repository)
   - [System-wide Launcher](#system-wide-launcher)
   - [Dependencies](#dependencies)
3. [Project Structure](#3-project-structure)
4. [Usage](#4-usage)
   - [Starting the Dashboard](#starting-the-dashboard)
   - [Main Menu](#main-menu)
   - [Nemesis Launcher Sub-menu](#nemesis-launcher-sub-menu)
   - [General Attacks Sub-menu](#general-attacks-sub-menu)
   - [CVE Exploits Sub-menu](#cve-exploits-sub-menu)
   - [About Sub-menu](#about-sub-menu)
5. [Module Management](#5-module-management)
   - [How Cloning Works](#how-cloning-works)
   - [Updating / Re-cloning a Module](#updating--re-cloning-a-module)
6. [Tool Descriptions](#6-tool-descriptions)
7. [Customisation & Configuration](#7-customisation--configuration)
8. [Updating the Dashboard](#8-updating-the-dashboard)
9. [Troubleshooting & FAQ](#9-troubleshooting--faq)
10. [Legal & Ethical Disclaimer](#10-legal--ethical-disclaimer)

---

## 1. Introduction

**Project Nemesis** is an educational pentesting framework focused on **Windows Services security**. It provides a unified dashboard to launch a collection of offensive security tools, each targeting different network protocols or attack vectors.

The project is modular by design – every tool is a separate GitHub repository that can be cloned, updated, and run directly from the dashboard. All modules are written in Python 3 and intended for use in **isolated lab environments** only.

---

## 2. Installation & Setup

### Clone the Repository

```bash
git clone https://github.com/ErfanNahidi/Project-Nemesis.git
cd Project-Nemesis
chmod +x nemesis.sh
```

### System-wide Launcher (optional)

Inside the dashboard, navigate to **Nemesis Launcher → Install**.  
This creates a `/usr/local/bin/nemesis` symlink, allowing you to type `nemesis` from any terminal.

### Dependencies

- **bash** 4.0+
- **git**
- **python3** and **pip3** (for individual tools)
- **sudo** privileges (tools perform raw packet operations)

The dashboard checks for `git` on startup; each tool installs its own Python dependencies automatically when first run.

---

## 3. Project Structure

```
Project-Nemesis/
├── nemesis.sh                 # Main dashboard script
├── utils/
│   └── helpers.sh             # Shared functions (logo, banners, tool handler)
├── scripts/
│   ├── general.sh             # General Attacks sub-menu
│   ├── cve.sh                 # CVE Exploits sub-menu (placeholder)
│   ├── launcher.sh            # Launcher install/update/remove
│   └── about.sh               # About menus
├── modules/                   # All cloned attack tools land here
│   ├── Nemesis-Scanner/
│   ├── Nemesis-DHCP-Havoc/
│   └── ...
├── LICENSE
├── README.md
└── manual.md
```

- **`modules/`** – automatically populated when you select a tool for the first time.
- **`utils/helpers.sh`** – contains all core logic (colours, banner, tool cloning/running). Other scripts `source` this file.

---

## 4. Usage

### Starting the Dashboard

```bash
./nemesis.sh
```

If you installed the launcher, simply type:

```bash
nemesis
```

The dashboard will check for `git` and then present the main menu.

### Main Menu

```
  [1] Nemesis Launcher (install/update/remove)
  [2] General Attacks
  [3] CVE Exploits
  [4] About
  [0] Exit
```

Navigate by typing the number and pressing Enter.

### Nemesis Launcher Sub-menu

```
  [1] Install   – make 'nemesis' available system-wide
  [2] Remove    – remove 'nemesis' command
  [3] Update    – pull latest dashboard from GitHub
  [0] Back to main menu
```

- **Install**: Creates a symlink `/usr/local/bin/nemesis` pointing to the current script.
- **Remove**: Deletes that symlink.
- **Update**: Fetches the latest dashboard code from the official repository.

### General Attacks Sub-menu

```
  [1] Scanner
  [2] DHCP Havoc
  [3] DoS
  [4] Sniffer
  [5] AD Reaper (Empty)
  [6] SMB Phantom (Empty)
  [7] DNS
  [8] RCP (Empty)
  [0] Back to main menu
```

Each option launches the corresponding tool. On first use, the tool will be cloned from GitHub into `modules/`. Subsequent selections give you the choice to **run** or **re‑clone** (update) the tool.

### CVE Exploits Sub-menu

Currently a placeholder – displays **“Coming soon…”**. This is where future CVE‑specific attack modules will reside.

### About Sub-menu

```
  [1] About Me
  [2] About this Project
  [0] Return to main menu
```

Displays information about the author and the project’s educational purpose.

---

## 5. Module Management

### How Cloning Works

When you select a tool from the **General Attacks** menu:

- The dashboard checks for the tool’s folder inside `modules/`.
- If absent → it runs `git clone <repo-url>` into that folder, installs Python dependencies, and offers to run it.
- If present → it gives you the choice to **run** the tool or **re‑clone** (wipe and pull fresh).

All tools are run via:

```bash
sudo python3 <module>/cli.py
```

### Updating / Re-cloning a Module

Inside a module’s menu, choose option `[2] Reclone (update)`. This **deletes** the local folder and clones it again, ensuring you have the latest code and dependencies.

---

## 6. Tool Descriptions

| Tool             | Repository (GitHub)                              | Purpose                                      |
|------------------|--------------------------------------------------|----------------------------------------------|
| **Scanner**       | `ErfanNahidi/Nemesis-Scanner`                    | Network reconnaissance & vulnerability mapping |
| **DHCP Havoc**    | `ErfanNahidi/Nemesis-DHCP-Havoc`                 | DHCP exhaustion / rogue server attacks        |
| **DoS**           | `ErfanNahidi/Nemesis-DoS-Engine`                 | Denial‑of‑Service testing (lab only)          |
| **Sniffer**       | `ErfanNahidi/Nemesis-Sniffiner`                  | Network packet capture & analysis             |
| **AD Reaper**     | `ErfanNahidi/Nemesis-AD-Reaper`                  | Active Directory enumeration (coming)         |
| **SMB Phantom**   | `ErfanNahidi/Nemesis-SMB-Phantom`                | SMB share enumeration / exploit (coming)      |
| **DNS**           | `ErfanNahidi/Nemesis-DNS-Hydra`                  | DNS spoofing / cache poisoning                |
| **RCP**           | –                                                | Reserved for future RPC attacks               |

> ⚠️ All tools require **root** and are strictly for educational use in isolated labs.

---

## 7. Customisation & Configuration

- **Colours**: Automatically disabled if output is not a terminal (e.g., piping to file).
- **New tools**: To add a new module, edit `scripts/general.sh` and insert a new menu entry calling `tool_handler "<repo-url>"`.
- **CVE module**: When ready, replace the placeholder in `scripts/cve.sh` with actual logic.
- **Tool handler**: The cloning logic is in `utils/helpers.sh` – you can modify paths or add pre‑run hooks.

---

## 8. Updating the Dashboard

The launcher update function (`[3] Update`) performs:

1. Verifies the script is inside a Git repository.
2. Checks if the remote matches the official URL (`https://github.com/ErfanNahidi/Project-Nemesis`).
3. Executes `git pull`.

If you made local changes, Git will attempt to merge them; conflicts may need manual resolution.

---

## 9. Troubleshooting & FAQ

### 9.1 “git is not installed”
Install git: `sudo apt install git` (Debian/Ubuntu) or `sudo dnf install git` (Fedora).

### 9.2 “No cli.py found”
The selected tool may not have a `cli.py` entry point. The dashboard will display an error and return to the menu.

### 9.3 Permission denied / “Operation not permitted”
SYN scans and most network attacks require **root**. Run the dashboard as a normal user – it will automatically use `sudo` when launching a tool.

### 9.4 “pip not found”
Install `pip3`: `sudo apt install python3-pip`.

### 9.5 Can I run tools outside the dashboard?
Yes – navigate to `modules/<tool-name>/` and execute `sudo python3 cli.py` directly. The dashboard just automates this for convenience.

---

## 10. Legal & Ethical Disclaimer

**Project Nemesis is an educational framework designed solely for authorised security testing in controlled lab environments.**

- You must own the network or have **explicit written permission** before running any attack.
- Unauthorised use against production systems is **illegal** and **unethical**.
- The author(s) assume **no liability** for any misuse, damage, or legal consequences.

By using this software, you agree to take **full responsibility** for your actions.

---

*Stay curious. Stay authorised.*  
— Erfan Nahidi