# ⚔️ Project Nemesis

<p align="center">
  <img src="Logo.png" width="300" alt="Project Nemesis Logo">
</p>

<h1 align="center">Project Nemesis</h1>

<p align="center">
  <strong>Windows Services Security Pentest Framework</strong>
</p>

<p align="center">
  A modular command-line platform for network reconnaissance, protocol analysis,<br>
  security testing, and authorized offensive security research.
</p>

<p align="center">
  <a href="README_FA.md">🇮🇷 فارسی</a>
</p>

---

## ⚡ Overview

**Project Nemesis** is a modular security testing framework designed to bring multiple Windows and network security tools together under a single command-line interface.

Instead of managing every security utility independently, Nemesis provides a centralized dashboard for discovering, installing, updating, and launching specialized security modules.

The framework is focused on **Windows Services, network protocols, infrastructure security, and penetration testing workflows**, with individual modules targeting specific protocols, services, and attack surfaces.

> **⚠️ Project Nemesis is intended for authorized security assessments, research, education, and isolated laboratory environments only.**

---

## 🧠 Design Philosophy

Nemesis follows a simple principle:

> **One framework. Multiple security tools. One consistent workflow.**

Each tool operates as an independent module with its own repository, dependencies, and functionality. The main dashboard acts as an orchestration layer rather than tightly coupling the individual projects together.

This makes the framework easier to:

* Develop and maintain
* Extend with new modules
* Update individual tools independently
* Test modules in isolated environments
* Build custom security-testing workflows

---

## ✨ Core Features

### 🖥️ Interactive Dashboard

A terminal-based interface for accessing and managing all Nemesis modules from one place.

### 🧩 Modular Architecture

Each security utility is maintained as an independent project and loaded dynamically into the main framework.

### 📦 Automatic Module Deployment

Modules are automatically cloned from their GitHub repositories when they are required.

### 🔄 Module Updates

Existing modules can be recloned to retrieve the latest repository version.

### 🚀 Global Launcher

Nemesis can optionally install a system-wide `nemesis` command, allowing the framework to be launched from anywhere.

### 🐍 Python Tool Integration

Individual modules can use their own Python runtime and dependency requirements without introducing dependencies into the core dashboard.

### 🎓 Research & Training Oriented

The framework is designed primarily for:

* Penetration testing laboratories
* Security research
* Red Team training
* Network security education
* Windows infrastructure testing
* Protocol analysis

---

# 🧩 Modules

Project Nemesis currently integrates the following projects.

| Module                  | Repository                                                                  | Purpose                                                           |
| ----------------------- | --------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| 🔎 **Nemesis Scanner**  | [`Nemesis-Scanner`](https://github.com/ErfanNahidi/Nemesis-Scanner)         | Network reconnaissance, service discovery & vulnerability mapping |
| ☠️ **DHCP Havoc**       | [`Nemesis-DHCP-Havoc`](https://github.com/ErfanNahidi/Nemesis-DHCP-Havoc)   | DHCP security testing and exhaustion attacks                      |
| 💀 **DoS Engine**       | [`Nemesis-DoS-Engine`](https://github.com/ErfanNahidi/Nemesis-DoS-Engine)   | Denial-of-Service testing for controlled environments             |
| 🕵️ **Nemesis Sniffer** | [`Nemesis-Sniffiner`](https://github.com/ErfanNahidi/Nemesis-Sniffiner)     | Packet capture and network traffic analysis                       |
| ☠️ **AD Reaper**        | [`Nemesis-AD-Reaper`](https://github.com/ErfanNahidi/Nemesis-AD-Reaper)     | Active Directory reconnaissance and security testing              |
| 👻 **SMB Phantom**      | [`Nemesis-SMB-Phantom`](https://github.com/ErfanNahidi/Nemesis-SMB-Phantom) | SMB enumeration and security testing                              |
| 🐉 **DNS Hydra**        | [`Nemesis-DNS-Hydra`](https://github.com/ErfanNahidi/Nemesis-DNS-Hydra)     | DNS security testing, spoofing and poisoning research             |
| ⚙️ **RPC**              | —                                                                           | Reserved for future RPC-focused tooling                           |

> **Note:** Modules marked as future or development components may not yet be available in the main framework.

---

# 🏗️ Architecture

```text
                         ┌──────────────────────────┐
                         │      Project Nemesis     │
                         │     Main CLI Dashboard   │
                         └────────────┬─────────────┘
                                      │
                ┌─────────────────────┼─────────────────────┐
                │                     │                     │
                ▼                     ▼                     ▼
        ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
        │   Launcher   │      │ General      │      │     CVE      │
        │   Manager    │      │   Attacks    │      │   Exploits   │
        └──────┬───────┘      └──────┬───────┘      └──────────────┘
               │                     │
               │                     ├── Scanner
               │                     ├── DHCP Havoc
               │                     ├── DoS Engine
               │                     ├── Sniffer
               │                     ├── AD Reaper
               │                     ├── SMB Phantom
               │                     └── DNS Hydra
               │
               ▼
        ┌─────────────────────────────────────────┐
        │                  modules/                │
        │                                         │
        │  ├── Nemesis-Scanner                    │
        │  ├── Nemesis-DHCP-Havoc                 │
        │  ├── Nemesis-DoS-Engine                 │
        │  ├── Nemesis-Sniffiner                  │
        │  ├── Nemesis-AD-Reaper                  │
        │  ├── Nemesis-SMB-Phantom                │
        │  └── Nemesis-DNS-Hydra                  │
        └─────────────────────────────────────────┘
```

The framework itself contains the orchestration logic, while individual security capabilities remain isolated inside their respective repositories.

---

# 📂 Project Structure

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
└── LICENSE
```

### Component Responsibilities

| Component             | Responsibility                                        |
| --------------------- | ----------------------------------------------------- |
| `nemesis.sh`          | Main framework entry point                            |
| `utils/helpers.sh`    | Shared UI and framework helper functions              |
| `scripts/general.sh`  | Security tool selection and execution                 |
| `scripts/cve.sh`      | CVE / exploit functionality                           |
| `scripts/launcher.sh` | Installation, update, removal and launcher management |
| `scripts/about.sh`    | Project information                                   |
| `modules/`            | Automatically cloned security tools                   |

---

# 🚀 Installation

## Requirements

The framework itself has minimal dependencies:

* **Bash ≥ 4.0**
* **Git**
* **Python 3**
* **pip3**
* **sudo access**

Individual modules may require additional packages depending on their implementation.

---

## Clone Project Nemesis

```bash
git clone https://github.com/ErfanNahidi/Project-Nemesis.git
cd Project-Nemesis
```

Make the launcher executable:

```bash
chmod +x nemesis.sh
```

Run the framework:

```bash
./nemesis.sh
```

---

# 🕹️ Main Menu

The main dashboard provides access to the framework's core functions.

```text
┌──────────────────────────────────────────┐
│              PROJECT NEMESIS             │
├──────────────────────────────────────────┤
│                                          │
│  [1] Nemesis Launcher                    │
│  [2] General Attacks                     │
│  [3] CVE Exploits                        │
│  [4] About                               │
│  [0] Exit                                │
│                                          │
└──────────────────────────────────────────┘
```

### General Attacks

```text
[1] Scanner
[2] DHCP Havoc
[3] DoS Engine
[4] Sniffer
[5] AD Reaper
[6] SMB Phantom
[7] DNS Hydra
[8] RPC
[0] Back
```

---

# 🔧 Module Workflow

Nemesis is designed around a simple module lifecycle.

### 1. Select a module

Choose a security tool from the **General Attacks** menu.

### 2. Automatic cloning

If the selected module is not present locally, Nemesis clones its repository into:

```text
modules/
```

### 3. Dependency installation

The framework can prepare the Python dependencies required by the selected module.

### 4. Module execution

The selected tool is launched through the framework.

### 5. Updating

Existing modules can be recloned through the launcher to obtain the latest repository version.

---

# 📦 Launcher

The **Nemesis Launcher** provides management functionality for the framework and its components.

Typical operations include:

```text
[1] Install Launcher
[2] Remove Launcher
[3] Update Project
[4] Manage Modules
[0] Back
```

Once installed, the framework can be started globally:

```bash
nemesis
```

This avoids having to manually navigate to the project directory every time.

---

# 🔄 Updating

## Update Project Nemesis

From the framework:

```text
Nemesis Launcher
        ↓
      Update
```

Or manually:

```bash
git pull origin main
```

## Update a Module

Modules can be recloned through the launcher to synchronize them with their upstream repositories.

> **Important:** Module repositories are maintained independently from the main Project Nemesis repository.

---

# 🔐 Security Model

Project Nemesis intentionally separates the **framework layer** from the **security-tool layer**.

```text
Framework
   │
   ├── UI / Menu
   ├── Module discovery
   ├── Repository management
   ├── Dependency handling
   └── Execution
          │
          ▼
     Security Modules
```

This architecture allows new tools to be added without significantly modifying the core framework.

A future module can follow the same model:

```text
New Repository
      ↓
Module Definition
      ↓
Automatic Clone
      ↓
Dependency Setup
      ↓
Framework Integration
```

---

# 🧪 Security Testing Scope

Project Nemesis is intended to support controlled testing involving areas such as:

### Network Security

* Network reconnaissance
* Service discovery
* Traffic analysis
* Vulnerability identification
* Protocol security research

### Windows Services

* DHCP
* DNS
* SMB
* RPC
* Active Directory
* Windows network services

### Offensive Security Research

* Protocol abuse research
* Misconfiguration testing
* Security-control validation
* Red Team laboratory exercises
* Attack simulation in isolated environments

---

# 🗺️ Roadmap

The framework is designed to grow into a broader modular Windows and network security platform.

### Current Direction

* [x] Centralized CLI dashboard
* [x] Modular tool loading
* [x] Git-based module deployment
* [x] Module update workflow
* [x] Global launcher
* [x] Network reconnaissance tooling
* [x] DHCP security tooling
* [x] Packet analysis tooling
* [x] DNS security tooling

### Planned

* [ ] Improved module discovery
* [ ] Better dependency management
* [ ] Module version tracking
* [ ] Module health/status detection
* [ ] Unified configuration system
* [ ] Better logging and error reporting
* [ ] CVE module integration
* [ ] RPC security module
* [ ] Expanded Active Directory tooling
* [ ] Expanded SMB security tooling
* [ ] Framework-wide configuration profiles

---

# 🛠️ Troubleshooting

### Permission denied

Make sure the main script is executable:

```bash
chmod +x nemesis.sh
```

### Git is unavailable

Install Git through your distribution's package manager.

### Python module dependency errors

Individual modules may require additional Python packages. Check the README of the affected module for module-specific requirements.

### Network tools fail without privileges

Some operations require elevated privileges:

```bash
sudo ./nemesis.sh
```

However, privilege requirements depend on the specific module being executed.

---

# 🤝 Contributing

Contributions are welcome.

You can contribute by:

* Creating new security modules
* Improving the framework architecture
* Fixing bugs
* Improving documentation
* Adding protocol support
* Improving the CLI experience
* Testing modules in controlled environments

For a new module, the recommended approach is to keep it as an **independent repository** and integrate it into Nemesis through the existing module architecture.

---

# ⚠️ Legal & Ethical Disclaimer

Project Nemesis is developed for **authorized security testing, education, research, and controlled laboratory environments**.

You are responsible for ensuring that you have explicit permission to test any system, network, host, service, or infrastructure targeted by these tools.

Do **not** use Project Nemesis against systems that you do not own or have explicit authorization to assess.

The author and contributors are not responsible for:

* Unauthorized use
* Service disruption
* Data loss
* Infrastructure damage
* Security incidents
* Any other consequences resulting from misuse

> **Use responsibly. Test only systems you are authorized to test.**

---

# 📜 License

Project Nemesis is released under the **MIT License**.

See [`LICENSE`](LICENSE) for the complete license text.

---

# 🔗 Project Links

### Main Framework

**Project Nemesis**
https://github.com/ErfanNahidi/Project-Nemesis

### Modules

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

### ⚔️ Project Nemesis

**Modular. Offensive. Educational.**

*Stay curious. Stay authorised.*

</div>
