<p align="center">
  <img src="Logo.png" width="300" alt="Nemesis Scanner Logo">

  <h1 align="center">Nemesis Scanner</h1>

  <p align="center">
    Advanced Network Reconnaissance & Vulnerability Scanner
  </p>
</p>

---

[🇮🇷 فارسی](README_FA.md)


<p align="center">
  <h1 align="center">Project Nemesis</h1>
  <p align="center"><em>Windows Services Security Pentest Framework</em></p>
</p>

---

## ⚡ Overview

**Project Nemesis** is a modular, educational pentesting dashboard focused on **Windows Services security**.  
It provides a unified command‑line interface to discover, clone, update, and run a collection of offensive security tools – each targeting a specific protocol or attack vector.

All tools are designed for **isolated lab environments** and are intended for **authorised security training** only.

---

## 🧩 Features

- 🖥️ **Interactive Dashboard** – clean terminal UI with colourised menus
- 🧰 **Modular Toolset** – scanner, DHCP havoc, DoS, sniffer, AD/SMB/DNS attacks
- 📦 **One‑Click Cloning** – automatically fetches each tool from its own GitHub repo
- 🔄 **Easy Updates** – reclone any module to get the latest version
- 🔗 **System‑wide Launcher** – optional `nemesis` command available anywhere
- 🎓 **Educational Focus** – built for learning, not production use

---

## 🚀 Quick Start

```bash
# Clone the dashboard
git clone https://github.com/ErfanNahidi/Project-Nemesis.git
cd Project-Nemesis

# Make it executable
chmod +x nemesis.sh

# Run
./nemesis.sh
```

> 💡 **Tip:** Use the built‑in launcher to install a global `nemesis` command.

---

## 📂 Project Structure

```
Project-Nemesis/
├── nemesis.sh              # Main entry point
├── utils/
│   └── helpers.sh          # Shared functions (UI, tool handler)
├── scripts/
│   ├── general.sh          # General Attacks menu
│   ├── cve.sh              # CVE Exploits (placeholder)
│   ├── launcher.sh         # Install / remove / update
│   └── about.sh            # Author & project info
├── modules/                # Cloned tools land here automatically
├── LICENSE
└── README.md
```

---

## 🕹️ Main Menu

```
  [1] Nemesis Launcher (install/update/remove)
  [2] General Attacks
  [3] CVE Exploits
  [4] About
  [0] Exit
```

### General Attacks Sub‑menu

```
  [1] Scanner          – network reconnaissance & CVE mapping
  [2] DHCP Havoc       – DHCP exhaustion / rogue server
  [3] DoS              – Denial‑of‑Service testing
  [4] Sniffer          – packet capture & analysis
  [5] AD Reaper        – Active Directory enumeration (coming soon)
  [6] SMB Phantom      – SMB share enumeration / exploit (coming soon)
  [7] DNS              – DNS spoofing / cache poisoning
  [8] RCP              – (reserved for future RPC attacks)
```

---

## 🔧 Module Workflow

1. **Select a tool** from the menu.  
2. If not cloned yet → automatically downloads from GitHub into `modules/`.  
3. The tool’s Python dependencies are installed automatically.  
4. You can **run** the tool or **reclone** it later to get updates.

All tools are launched with:

```bash
sudo python3 <module>/cli.py
```

---

## 📦 Dependencies

- **bash** ≥ 4.0
- **git**
- **python3** & **pip3** (for individual tools)
- **sudo** access (network tools require root)

The dashboard itself has **no external dependencies**.

---

## 🧪 Included Modules

| Module          | Repository                                        | Description                          |
|-----------------|---------------------------------------------------|--------------------------------------|
| Scanner         | `ErfanNahidi/Nemesis-Scanner`                     | Network recon & vuln mapping         |
| DHCP Havoc      | `ErfanNahidi/Nemesis-DHCP-Havoc`                  | DHCP exhaustion attacks              |
| DoS Engine      | `ErfanNahidi/Nemesis-DoS-Engine`                  | DoS testing (lab only)               |
| Sniffer         | `ErfanNahidi/Nemesis-Sniffiner`                   | Packet capture & analysis            |
| AD Reaper       | `ErfanNahidi/Nemesis-AD-Reaper`                   | AD enumeration (to be released)      |
| SMB Phantom     | `ErfanNahidi/Nemesis-SMB-Phantom`                 | SMB exploitation (to be released)    |
| DNS Hydra       | `ErfanNahidi/Nemesis-DNS-Hydra`                   | DNS spoofing / poisoning             |
| RCP             | –                                                 | Future RPC attacks                   |

---

## 🔄 Updating the Dashboard

Use the built‑in launcher:

1. From the main menu, go to **[1] Nemesis Launcher**.  
2. Select **[3] Update** – pulls the latest dashboard code from GitHub.

Or manually:  
```bash
git pull origin main
```

---

## ⚠️ Legal & Ethical Disclaimer

This project is provided for **educational and authorised testing purposes only**.  
**Do not use these tools against any system you do not own or have explicit permission to test.**

The author assumes **no liability** for any misuse or damage caused by this software.

---

## 📜 License

MIT License – see [LICENSE](LICENSE) for details.

---

*Stay curious. Stay authorised.*  
— Erfan Nahidi
