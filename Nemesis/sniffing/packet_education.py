#!/usr/bin/env python3
# type: ignore
"""
Packet Education Script
This script helps you understand network packet structures and protocols.
"""

import scapy.all as scapy
import struct

def show_ip_header_structure():
    """Demonstrate IP header structure"""
    print("=" * 60)
    print("IP HEADER STRUCTURE")
    print("=" * 60)
    
    # Create a sample IP packet
    ip_packet = scapy.IP(src="192.168.1.100", dst="8.8.8.8")  # type: ignore
    
    print("IP Header Fields:")
    print(f"Version: {ip_packet.version} (IPv4)")
    print(f"IHL (Header Length): {ip_packet.ihl * 4} bytes")
    print(f"Type of Service: {ip_packet.tos}")
    print(f"Total Length: {ip_packet.len} bytes")
    print(f"Identification: {ip_packet.id}")
    print(f"Flags: {ip_packet.flags}")
    print(f"Fragment Offset: {ip_packet.frag}")
    print(f"Time to Live: {ip_packet.ttl}")
    print(f"Protocol: {ip_packet.proto} ({ip_packet.proto})")
    print(f"Header Checksum: {hex(ip_packet.chksum)}")
    print(f"Source IP: {ip_packet.src}")
    print(f"Destination IP: {ip_packet.dst}")
    
    print("\nRaw IP Header (hex):")
    raw_header = bytes(ip_packet)[:20]  # First 20 bytes
    for i in range(0, len(raw_header), 4):
        chunk = raw_header[i:i+4]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  {i:02d}: {hex_str}")

def show_tcp_header_structure():
    """Demonstrate TCP header structure"""
    print("\n" + "=" * 60)
    print("TCP HEADER STRUCTURE")
    print("=" * 60)
    
    # Create a sample TCP packet
    tcp_packet = scapy.TCP(sport=12345, dport=80, flags="S")  # type: ignore  # SYN flag
    
    print("TCP Header Fields:")
    print(f"Source Port: {tcp_packet.sport}")
    print(f"Destination Port: {tcp_packet.dport}")
    print(f"Sequence Number: {tcp_packet.seq}")
    print(f"Acknowledgment Number: {tcp_packet.ack}")
    print(f"Data Offset: {tcp_packet.dataofs * 4} bytes")
    print(f"Reserved: {tcp_packet.reserved}")
    print(f"Flags: {tcp_packet.flags}")
    print(f"  - FIN: {bool(tcp_packet.flags & 1)}")
    print(f"  - SYN: {bool(tcp_packet.flags & 2)}")
    print(f"  - RST: {bool(tcp_packet.flags & 4)}")
    print(f"  - PSH: {bool(tcp_packet.flags & 8)}")
    print(f"  - ACK: {bool(tcp_packet.flags & 16)}")
    print(f"  - URG: {bool(tcp_packet.flags & 32)}")
    print(f"Window Size: {tcp_packet.window}")
    print(f"Checksum: {hex(tcp_packet.chksum)}")
    print(f"Urgent Pointer: {tcp_packet.urgptr}")
    
    print("\nRaw TCP Header (hex):")
    raw_header = bytes(tcp_packet)[:20]  # First 20 bytes
    for i in range(0, len(raw_header), 4):
        chunk = raw_header[i:i+4]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  {i:02d}: {hex_str}")

def show_udp_header_structure():
    """Demonstrate UDP header structure"""
    print("\n" + "=" * 60)
    print("UDP HEADER STRUCTURE")
    print("=" * 60)
    
    # Create a sample UDP packet
    udp_packet = scapy.UDP(sport=12345, dport=53)  # type: ignore  # DNS port
    
    print("UDP Header Fields:")
    print(f"Source Port: {udp_packet.sport}")
    print(f"Destination Port: {udp_packet.dport}")
    print(f"Length: {udp_packet.len} bytes")
    print(f"Checksum: {hex(udp_packet.chksum)}")
    
    print("\nRaw UDP Header (hex):")
    raw_header = bytes(udp_packet)[:8]  # First 8 bytes
    for i in range(0, len(raw_header), 4):
        chunk = raw_header[i:i+4]
        hex_str = ' '.join(f'{b:02x}' for b in chunk)
        print(f"  {i:02d}: {hex_str}")

def show_common_ports():
    """Show common ports and their services"""
    print("\n" + "=" * 60)
    print("COMMON PORTS AND SERVICES")
    print("=" * 60)
    
    common_ports = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP-Server",
        68: "DHCP-Client",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        123: "NTP",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        389: "LDAP",
        443: "HTTPS",
        465: "SMTPS",
        514: "Syslog",
        515: "LPR",
        587: "SMTP-Submission",
        631: "IPP",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9000: "Web Alternative"
    }
    
    print("Port | Service")
    print("-" * 30)
    for port, service in sorted(common_ports.items()):
        print(f"{port:4d} | {service}")

def show_protocol_comparison():
    """Compare different protocols"""
    print("\n" + "=" * 60)
    print("PROTOCOL COMPARISON")
    print("=" * 60)
    
    protocols = {
        "TCP": {
            "Type": "Connection-oriented",
            "Reliability": "Guaranteed",
            "Ordering": "Guaranteed",
            "Speed": "Slower",
            "Header Size": "20-60 bytes",
            "Use Cases": "Web browsing, email, file transfer"
        },
        "UDP": {
            "Type": "Connectionless",
            "Reliability": "Not guaranteed",
            "Ordering": "Not guaranteed",
            "Speed": "Faster",
            "Header Size": "8 bytes",
            "Use Cases": "DNS, DHCP, streaming, gaming"
        },
        "ICMP": {
            "Type": "Control protocol",
            "Reliability": "Not guaranteed",
            "Ordering": "Not applicable",
            "Speed": "Fast",
            "Header Size": "8 bytes",
            "Use Cases": "Ping, traceroute, error messages"
        }
    }
    
    for protocol, details in protocols.items():
        print(f"\n{protocol}:")
        for key, value in details.items():
            print(f"  {key}: {value}")

def demonstrate_packet_capture():
    """Demonstrate how packet capture works"""
    print("\n" + "=" * 60)
    print("PACKET CAPTURE DEMONSTRATION")
    print("=" * 60)
    
    print("When you capture packets, here's what happens:")
    print()
    print("1. Network Interface Card (NIC) receives all packets")
    print("2. Operating system filters packets based on your criteria")
    print("3. Scapy library captures the filtered packets")
    print("4. Each packet is analyzed for:")
    print("   - Source and destination IP addresses")
    print("   - Protocol type (TCP, UDP, ICMP, etc.)")
    print("   - Port numbers")
    print("   - Packet length")
    print("   - Payload data")
    print()
    print("5. Statistics are collected:")
    print("   - Protocol distribution")
    print("   - Most active IP addresses")
    print("   - Most used ports")
    print("   - Total packet count")
    
    print("\nExample packet flow:")
    print("Browser → HTTP Request → TCP Packet → IP Packet → Network")
    print("Network → IP Packet → TCP Packet → HTTP Response → Browser")

def main():
    print("NETWORK PACKET EDUCATION")
    print("=" * 60)
    print("This script helps you understand network packet structures")
    print("and how the network sniffer analyzes them.")
    print()
    
    try:
        show_ip_header_structure()
        show_tcp_header_structure()
        show_udp_header_structure()
        show_common_ports()
        show_protocol_comparison()
        demonstrate_packet_capture()
        
        print("\n" + "=" * 60)
        print("EDUCATION COMPLETE!")
        print("=" * 60)
        print("Now you understand:")
        print("✓ How packet headers are structured")
        print("✓ What information each protocol contains")
        print("✓ Common ports and their services")
        print("✓ Differences between TCP, UDP, and ICMP")
        print("✓ How packet capture works")
        print()
        print("You're ready to use the network sniffer effectively!")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        print("Make sure you have the required dependencies installed.")

if __name__ == "__main__":
    main() 