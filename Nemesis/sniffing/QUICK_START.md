# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Windows Users - Install Npcap

Download and install Npcap from: https://npcap.com/
- Use default installation settings
- This is required for packet capture on Windows

### 3. Run as Administrator

**Windows:**
- Right-click Command Prompt or PowerShell
- Select "Run as administrator"
- Navigate to your project directory

**Linux/macOS:**
```bash
sudo python3 network_sniffer.py
```

### 4. Test the Sniffer

```bash
# List available interfaces
python network_sniffer.py --list-interfaces

# Capture all packets (Ctrl+C to stop)
python network_sniffer.py

# Capture only HTTP traffic
python network_sniffer.py -f "tcp port 80"

# Capture only 10 packets
python network_sniffer.py -c 10
```

### 5. Generate Test Traffic

In another terminal, run the demo script to generate test traffic:

```bash
python demo.py
```

## 🎯 Common Commands

| Command | Description |
|---------|-------------|
| `python network_sniffer.py` | Capture all packets |
| `python network_sniffer.py -i "Wi-Fi"` | Capture on specific interface |
| `python network_sniffer.py -f "tcp port 443"` | Capture HTTPS traffic |
| `python network_sniffer.py -f "udp port 53"` | Capture DNS traffic |
| `python network_sniffer.py -c 50` | Capture 50 packets |
| `python network_sniffer.py --list-interfaces` | Show available interfaces |

## 🔧 Troubleshooting

### "Permission Denied" Error
- **Windows**: Run as Administrator
- **Linux/macOS**: Use `sudo`

### "No Packets Captured"
- Check if interface name is correct
- Try without specifying interface
- Ensure network connectivity

### Import Errors
- Run: `pip install -r requirements.txt`
- Ensure Python 3.7+ is installed

### Windows: "No interfaces found"
- Install Npcap from https://npcap.com/
- Restart your computer after installation

## 📚 Learn More

1. **Understand Protocols**: Run `python packet_education.py`
2. **Generate Test Traffic**: Run `python demo.py`
3. **Read the Full Documentation**: See `README.md`

## ⚠️ Important Notes

- **Legal Use Only**: Only capture traffic on networks you own
- **Educational Purpose**: This tool is for learning network protocols
- **Privacy**: Be aware that packet capture can reveal sensitive data

## 🎉 You're Ready!

Start exploring network traffic and understanding how data flows through networks! 