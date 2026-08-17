# ⚔️ Project Nemesis — User Manual

<p align="center">
  <strong>Windows Services Security Pentest Framework</strong>
</p>

<p align="center">
  Complete usage and administration guide for Project Nemesis
</p>

---

# 📖 Table of Contents

* [Introduction](#-introduction)
* [Requirements](#-requirements)
* [Installation](#-installation)
* [First Run](#-first-run)
* [Main Dashboard](#-main-dashboard)
* [Nemesis Launcher](#-nemesis-launcher)
* [Module Management](#-module-management)
* [Running Modules](#-running-modules)
* [Module Categories](#-module-categories)
* [Permissions](#-permissions)
* [Updating Project Nemesis](#-updating-project-nemesis)
* [Troubleshooting](#-troubleshooting)
* [Adding a New Module](#-adding-a-new-module)
* [Recommended Lab Setup](#-recommended-lab-setup)
* [Operational Guidelines](#-operational-guidelines)
* [Uninstallation](#-uninstallation)
* [Project Structure](#-project-structure)
* [FAQ](#-faq)
* [Legal Notice](#-legal-notice)

---

# 📌 Introduction

**Project Nemesis** is a modular command-line framework for managing a collection of security testing tools focused primarily on:

* Windows services
* Network protocols
* Infrastructure security
* Protocol analysis
* Reconnaissance
* Vulnerability assessment
* Security research

The framework provides a unified interface for downloading, updating, managing, and executing independent security modules.

Each module is developed independently and can have its own dependencies, documentation, and execution requirements.

---

# ⚙️ Requirements

## Operating System

Nemesis is primarily intended for Linux-based environments.

Recommended environments include:

* Fedora
* Debian
* Ubuntu
* Kali Linux
* Arch Linux

A properly configured Linux networking stack is recommended for network-oriented modules.

---

## Required Software

The main framework requires:

```text
Bash >= 4.0
Git
Python 3
pip3
sudo
```

Verify the environment:

```bash
bash --version
git --version
python3 --version
pip3 --version
sudo --version
```

---

# 🚀 Installation

## 1. Clone the Repository

```bash
git clone https://github.com/ErfanNahidi/Project-Nemesis.git
```

Enter the project directory:

```bash
cd Project-Nemesis
```

---

## 2. Make the Framework Executable

```bash
chmod +x nemesis.sh
```

---

## 3. Start Nemesis

```bash
./nemesis.sh
```

The main dashboard should appear.

---

# 🧪 First Run

On the first execution, Nemesis may not have any modules installed locally.

When a module is selected:

```text
Module not found
        ↓
Repository lookup
        ↓
Git clone
        ↓
Module deployment
        ↓
Dependency preparation
        ↓
Module execution
```

This means you do not necessarily need to manually clone every module before using the framework.

---

# 🕹️ Main Dashboard

The main interface provides access to the primary Framework functions.

```text
╔══════════════════════════════════════════╗
║             PROJECT NEMESIS              ║
╠══════════════════════════════════════════╣
║                                          ║
║  [1] Nemesis Launcher                    ║
║  [2] General Attacks                     ║
║  [3] CVE Exploits                        ║
║  [4] About                               ║
║  [0] Exit                                ║
║                                          ║
╚══════════════════════════════════════════╝
```

---

# 1️⃣ Nemesis Launcher

The Launcher is responsible for managing the Framework and installed modules.

Depending on the current version, available options may include:

```text
[1] Install Launcher
[2] Remove Launcher
[3] Update Project
[4] Manage Modules
[0] Back
```

---

## Install Global Launcher

The launcher allows the `nemesis` command to be made available system-wide.

After installation, instead of:

```bash
cd Project-Nemesis
./nemesis.sh
```

you can use:

```bash
nemesis
```

from any directory.

---

## Remove Global Launcher

Use the Launcher removal option when you no longer want the global command.

This removes the system-wide launcher and does not necessarily remove the Project Nemesis source directory.

---

# 2️⃣ General Attacks

The **General Attacks** menu provides access to individual security modules.

```text
╔══════════════════════════════════════════╗
║             GENERAL ATTACKS              ║
╠══════════════════════════════════════════╣
║                                          ║
║  [1] Scanner                             ║
║  [2] DHCP Havoc                          ║
║  [3] DoS Engine                          ║
║  [4] Sniffer                             ║
║  [5] AD Reaper                           ║
║  [6] SMB Phantom                         ║
║  [7] DNS Hydra                           ║
║  [8] RPC                                 ║
║  [0] Back                                ║
║                                          ║
╚══════════════════════════════════════════╝
```

---

# 🔎 Nemesis Scanner

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-Scanner
```

### Purpose

Network reconnaissance and vulnerability assessment.

Typical functionality includes:

* Host discovery
* Port scanning
* Service detection
* Version identification
* Vulnerability mapping
* Network reconnaissance

The Scanner should be used against authorized targets only.

---

# ☠️ Nemesis DHCP Havoc

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-DHCP-Havoc
```

### Purpose

DHCP security assessment and protocol-level testing.

Potential areas include:

* DHCP starvation testing
* Rogue DHCP research
* DHCP message analysis
* DHCP reconnaissance
* DHCP security validation

DHCP testing can disrupt network connectivity, so it should be performed only inside a controlled environment or against infrastructure explicitly authorized for testing.

---

# 💀 Nemesis DoS Engine

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-DoS-Engine
```

### Purpose

Controlled Denial-of-Service testing and performance/security research.

Typical areas include:

* HTTP load testing
* ICMP traffic generation
* High-rate connection testing
* Traffic stress testing

DoS functionality should only be executed against dedicated laboratory systems or explicitly authorized targets.

---

# 🕵️ Nemesis Sniffer

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-Sniffiner
```

### Purpose

Network traffic capture and analysis.

Typical use cases:

* Packet capture
* Protocol inspection
* Traffic analysis
* Troubleshooting
* Security research

Packet capture normally requires elevated privileges.

---

# ☠️ Nemesis AD Reaper

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-AD-Reaper
```

### Purpose

Active Directory security assessment.

Possible areas include:

* Domain enumeration
* User discovery
* Group discovery
* Domain controller reconnaissance
* AD security research

Use only against domains and environments that you are authorized to assess.

---

# 👻 Nemesis SMB Phantom

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-SMB-Phantom
```

### Purpose

SMB security assessment and enumeration.

Potential functionality includes:

* SMB service discovery
* Share enumeration
* SMB configuration inspection
* Authentication testing
* Security research

---

# 🐉 Nemesis DNS Hydra

**Repository:**

```text
https://github.com/ErfanNahidi/Nemesis-DNS-Hydra
```

### Purpose

DNS security research and protocol testing.

Possible areas include:

* DNS reconnaissance
* DNS response analysis
* Spoofing research
* Cache-poisoning research
* DNS configuration testing

DNS manipulation should be limited to controlled environments or authorized assessments.

---

# ⚙️ RPC Module

The RPC module is reserved for future RPC-focused security functionality.

Possible future areas:

* RPC endpoint discovery
* Service enumeration
* Protocol analysis
* Windows RPC security research

---

# 📦 Module Management

Modules are stored inside:

```text
modules/
```

Example:

```text
modules/
├── Nemesis-Scanner/
├── Nemesis-DHCP-Havoc/
├── Nemesis-DoS-Engine/
├── Nemesis-Sniffiner/
├── Nemesis-AD-Reaper/
├── Nemesis-SMB-Phantom/
└── Nemesis-DNS-Hydra/
```

---

## Check Installed Modules

From the project directory:

```bash
ls -lah modules/
```

To inspect an individual module:

```bash
ls -lah modules/Nemesis-Scanner/
```

---

## Remove a Module Manually

Only remove a module when it is not currently running:

```bash
rm -rf modules/<module-name>
```

Example:

```bash
rm -rf modules/Nemesis-Scanner
```

The module can then be cloned again through the framework.

---

# ▶️ Running Modules

Nemesis normally handles module startup automatically.

A module may internally be started with a command similar to:

```bash
sudo python3 cli.py
```

However, the exact entry point depends on the module implementation.

Always consult the module's own documentation for module-specific arguments and configuration.

---

# 🔐 Permissions

Some security operations require root privileges.

Typical examples include:

* Raw packet generation
* Packet capture
* Low-level network operations
* Interface manipulation

Check your current privileges:

```bash
id
```

Check whether sudo is available:

```bash
sudo -v
```

Some modules may run without root privileges, while others require elevated access.

Avoid running the complete Framework as root unless the module actually requires it.

---

# 🔄 Updating Project Nemesis

## Update Framework

From the project directory:

```bash
git pull origin main
```

Or use:

```text
Nemesis Launcher
        ↓
Update Project
```

---

## Update Modules

A module can be refreshed through the Launcher.

Conceptually:

```text
Existing module
      ↓
Remove / reclone
      ↓
Latest repository version
```

Before updating production or important laboratory environments, consider checking the module repository for breaking changes.

---

# 🛠️ Troubleshooting

## `Permission denied`

Run:

```bash
chmod +x nemesis.sh
```

---

## `git: command not found`

Install Git using your Linux distribution's package manager.

---

## `python3: command not found`

Install Python 3 and verify:

```bash
python3 --version
```

---

## `pip3: command not found`

Install the Python package manager and verify:

```bash
pip3 --version
```

---

## Module fails to start

First inspect the module directory:

```bash
ls -lah modules/<module-name>
```

Check its documentation:

```bash
cat modules/<module-name>/README.md
```

Then inspect its dependency configuration, for example:

```bash
ls modules/<module-name>
```

Possible files include:

```text
requirements.txt
pyproject.toml
setup.py
```

---

## Git clone fails

Check network connectivity:

```bash
ping -c 3 github.com
```

Check GitHub access:

```bash
git ls-remote https://github.com/ErfanNahidi/Project-Nemesis.git
```

If you are behind a corporate proxy or restricted network, Git may require additional configuration.

---

## Module works manually but not through Nemesis

Compare the environment used by the Framework with the environment used during manual execution.

Check:

```bash
pwd
which python3
python3 --version
echo "$PATH"
```

Also check whether the Framework and the module expect different working directories.

---

# 🧩 Adding a New Module

Nemesis is designed to allow additional security tools to be integrated without turning the core repository into a monolithic codebase.

Recommended workflow:

```text
1. Create independent security tool
             ↓
2. Publish module repository
             ↓
3. Define module metadata
             ↓
4. Add repository URL
             ↓
5. Add module to menu
             ↓
6. Define execution entry point
             ↓
7. Test clone / update / execution
```

---

## Recommended Module Layout

A module should ideally have a predictable structure:

```text
Nemesis-New-Module/
├── cli.py
├── README.md
├── requirements.txt
├── LICENSE
└── ...
```

The Framework should not need to know the internal implementation details of the module beyond:

* Repository URL
* Local directory
* Entry point
* Required execution method
* Optional dependency configuration

---

# 🧪 Recommended Lab Environment

Because several Nemesis modules can generate disruptive traffic, a dedicated laboratory is strongly recommended.

A basic lab can consist of:

```text
                    ┌─────────────────────┐
                    │   Nemesis Host      │
                    │     Linux           │
                    └─────────┬───────────┘
                              │
                         Isolated LAN
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
          ▼                   ▼                   ▼
    ┌───────────┐       ┌───────────┐       ┌───────────┐
    │ Windows   │       │ Windows   │       │ Linux     │
    │ Server    │       │ Client    │       │ Target    │
    │ AD / DNS  │       │ SMB       │       │ Services  │
    └───────────┘       └───────────┘       └───────────┘
```

Recommended isolation methods include:

* VMware Workstation
* VMware ESXi
* VirtualBox
* KVM
* Proxmox
* Dedicated physical lab network

Avoid exposing intentionally vulnerable or disruptive test environments directly to the public Internet.

---

# 🧠 Operational Guidelines

Before starting a security assessment:

### Define the Scope

Document:

```text
Target IPs
Target networks
Target services
Allowed techniques
Testing window
Emergency contact
```

### Verify Authorization

Ensure you have explicit permission to conduct the assessment.

### Start with Reconnaissance

Use passive or low-impact discovery before running disruptive modules.

### Monitor the Environment

Watch:

```text
CPU
Memory
Network traffic
Service availability
System logs
Security logs
```

### Stop When Necessary

If a test causes unintended service degradation, terminate the operation and restore the affected service.

---

# 🧹 Uninstallation

## Remove Project Nemesis

Delete the cloned repository:

```bash
rm -rf Project-Nemesis
```

Only do this after removing any global launcher you no longer require.

---

## Remove Global Launcher

Use the Launcher:

```text
Nemesis Launcher
        ↓
Remove Launcher
```

If your installation uses a manually created system-wide executable, remove only the launcher created by your installation.

---

# 📂 Project Structure

Complete example:

```text
Project-Nemesis/
│
├── nemesis.sh
│
├── utils/
│   └── helpers.sh
│
├── scripts/
│   ├── general.sh
│   ├── cve.sh
│   ├── launcher.sh
│   └── about.sh
│
├── modules/
│   ├── Nemesis-Scanner/
│   ├── Nemesis-DHCP-Havoc/
│   ├── Nemesis-DoS-Engine/
│   ├── Nemesis-Sniffiner/
│   ├── Nemesis-AD-Reaper/
│   ├── Nemesis-SMB-Phantom/
│   └── Nemesis-DNS-Hydra/
│
├── Logo.png
├── README.md
├── README_FA.md
├── MANUAL.md
└── LICENSE
```

---

# ❓ FAQ

## Do I need to install every module manually?

No. The Framework is designed to retrieve modules when they are required.

---

## Can I run Nemesis without root?

Yes, depending on the module.

Some modules require elevated privileges for low-level networking operations.

---

## Can modules be updated independently?

Yes. Each module has its own repository and development lifecycle.

---

## Can I add my own tool?

Yes. The modular architecture is specifically designed for this purpose.

---

## Is Nemesis a replacement for Nmap, Impacket, Wireshark or similar tools?

No.

Nemesis is an **orchestration and integration framework** around specialized security tools. Individual modules may internally rely on existing security utilities and libraries.

---

## Can I use Nemesis against public IP addresses?

Only when you have explicit authorization to test them.

---

# 🔗 Project Links

## Main Framework

**Project Nemesis**

https://github.com/ErfanNahidi/Project-Nemesis

## Modules

* **Nemesis Scanner**
  https://github.com/ErfanNahidi/Nemesis-Scanner

* **Nemesis DHCP Havoc**
  https://github.com/ErfanNahidi/Nemesis-DHCP-Havoc

* **Nemesis DoS Engine**
  https://github.com/ErfanNahidi/Nemesis-DoS-Engine

* **Nemesis Sniffer**
  https://github.com/ErfanNahidi/Nemesis-Sniffiner

* **Nemesis AD Reaper**
  https://github.com/ErfanNahidi/Nemesis-AD-Reaper

* **Nemesis SMB Phantom**
  https://github.com/ErfanNahidi/Nemesis-SMB-Phantom

* **Nemesis DNS Hydra**
  https://github.com/ErfanNahidi/Nemesis-DNS-Hydra

---

# 👤 Author

**Erfan Nahidi**

Security Researcher • Infrastructure & Network Engineer

GitHub:

https://github.com/ErfanNahidi

---

<div align="center">

# ⚔️ Project Nemesis

**Modular. Offensive. Educational.**

*Stay curious. Stay authorised.*

</div>
