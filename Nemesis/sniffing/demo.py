#!/usr/bin/env python3
# type: ignore
"""
Demo script to generate test network traffic for the network sniffer.
This script creates various types of network packets to demonstrate the sniffer's capabilities.
"""

import time
import threading
import socket
import requests
import scapy.all as scapy

def generate_icmp_traffic():
    """Generate ICMP (ping) traffic"""
    print("Generating ICMP traffic...")
    try:
        # Ping localhost
        ans, unans = scapy.sr(scapy.IP(dst="127.0.0.1")/scapy.ICMP(), timeout=1, verbose=0)  # type: ignore
        if ans:
            print("✓ ICMP packets sent successfully")
        else:
            print("✗ No ICMP response received")
    except Exception as e:
        print(f"✗ ICMP error: {e}")

def generate_dns_traffic():
    """Generate DNS traffic"""
    print("Generating DNS traffic...")
    try:
        # DNS query for google.com
        ans, unans = scapy.sr(scapy.IP(dst="8.8.8.8")/scapy.UDP(dport=53)/scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com")),  # type: ignore
                       timeout=2, verbose=0)
        if ans:
            print("✓ DNS packets sent successfully")
        else:
            print("✗ No DNS response received")
    except Exception as e:
        print(f"✗ DNS error: {e}")

def generate_http_traffic():
    """Generate HTTP traffic"""
    print("Generating HTTP traffic...")
    try:
        # Simple HTTP request
        response = requests.get("http://httpbin.org/get", timeout=5)
        if response.status_code == 200:
            print("✓ HTTP request successful")
        else:
            print(f"✗ HTTP request failed with status {response.status_code}")
    except Exception as e:
        print(f"✗ HTTP error: {e}")

def generate_tcp_traffic():
    """Generate TCP traffic"""
    print("Generating TCP traffic...")
    try:
        # TCP connection to a well-known port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('8.8.8.8', 53))
        sock.close()
        if result == 0:
            print("✓ TCP connection successful")
        else:
            print("✗ TCP connection failed")
    except Exception as e:
        print(f"✗ TCP error: {e}")

def generate_udp_traffic():
    """Generate UDP traffic"""
    print("Generating UDP traffic...")
    try:
        # UDP packet to a well-known port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.sendto(b"test", ('8.8.8.8', 53))
        sock.close()
        print("✓ UDP packet sent successfully")
    except Exception as e:
        print(f"✗ UDP error: {e}")

def main():
    print("Network Traffic Generator Demo")
    print("=" * 40)
    print("This script will generate various types of network traffic")
    print("to demonstrate the network sniffer's capabilities.")
    print()
    
    # Check if running with proper privileges
    try:
        # Try to create a raw socket (requires privileges)
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_socket.close()
        print("✓ Running with sufficient privileges")
    except PermissionError:
        print("⚠️  Warning: May need administrator/root privileges for full functionality")
    except Exception as e:
        print(f"⚠️  Warning: {e}")
    
    print()
    
    # Generate different types of traffic
    traffic_generators = [
        generate_icmp_traffic,
        generate_dns_traffic,
        generate_http_traffic,
        generate_tcp_traffic,
        generate_udp_traffic
    ]
    
    for generator in traffic_generators:
        generator()
        time.sleep(1)  # Small delay between different types
    
    print()
    print("Demo completed!")
    print("=" * 40)
    print("Now you can run the network sniffer to capture this traffic:")
    print()
    print("1. Open a new terminal/command prompt")
    print("2. Navigate to this directory")
    print("3. Run: python network_sniffer.py")
    print("4. In another terminal, run this demo again: python demo.py")
    print()
    print("This will show you real-time packet capture and analysis!")

if __name__ == "__main__":
    main() 