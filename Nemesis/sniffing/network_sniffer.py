#!/usr/bin/env python3
# type: ignore
"""
Basic Network Sniffer
A Python program to capture and analyze network traffic packets.
"""

import sys
import time
import argparse
from datetime import datetime
from collections import defaultdict
import signal
import os
import traceback

try:
    import scapy.all as scapy
    from colorama import init, Fore, Back, Style
    from tabulate import tabulate
    # from scapy.layers.inet import IGMP  # Removed, not needed and causes ImportError
except ImportError as e:
    print(f"Error: Missing required library. Please install dependencies: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class NetworkSniffer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.port_stats = defaultdict(int)
        self.captured_packets = []
        self.running = False
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}[!] Stopping packet capture...")
        self.running = False
        
    def get_protocol_name(self, packet):
        """Extract protocol name from packet"""
        # First check for built-in Scapy layers
        if packet.haslayer(scapy.TCP):  # type: ignore
            # Check for common application protocols based on ports
            if packet.haslayer(scapy.TCP):  # type: ignore
                tcp_layer = packet[scapy.TCP]  # type: ignore
                if tcp_layer.sport == 80 or tcp_layer.dport == 80:
                    return "HTTP"
                elif tcp_layer.sport == 443 or tcp_layer.dport == 443:
                    return "HTTPS"
                elif tcp_layer.sport == 22 or tcp_layer.dport == 22:
                    return "SSH"
                elif tcp_layer.sport == 21 or tcp_layer.dport == 21:
                    return "FTP"
                elif tcp_layer.sport == 23 or tcp_layer.dport == 23:
                    return "TELNET"
                elif tcp_layer.sport == 25 or tcp_layer.dport == 25:
                    return "SMTP"
                elif tcp_layer.sport == 110 or tcp_layer.dport == 110:
                    return "POP3"
                elif tcp_layer.sport == 143 or tcp_layer.dport == 143:
                    return "IMAP"
                elif tcp_layer.sport == 993 or tcp_layer.dport == 993:
                    return "IMAPS"
                elif tcp_layer.sport == 995 or tcp_layer.dport == 995:
                    return "POP3S"
                elif tcp_layer.sport == 587 or tcp_layer.dport == 587:
                    return "SMTP-Submission"
                elif tcp_layer.sport == 465 or tcp_layer.dport == 465:
                    return "SMTPS"
                elif tcp_layer.sport == 3389 or tcp_layer.dport == 3389:
                    return "RDP"
                elif tcp_layer.sport == 3306 or tcp_layer.dport == 3306:
                    return "MySQL"
                elif tcp_layer.sport == 5432 or tcp_layer.dport == 5432:
                    return "PostgreSQL"
                elif tcp_layer.sport == 1433 or tcp_layer.dport == 1433:
                    return "MSSQL"
                elif tcp_layer.sport == 1521 or tcp_layer.dport == 1521:
                    return "Oracle"
                elif tcp_layer.sport == 6379 or tcp_layer.dport == 6379:
                    return "Redis"
                elif tcp_layer.sport == 8080 or tcp_layer.dport == 8080:
                    return "HTTP-Alt"
                elif tcp_layer.sport == 8443 or tcp_layer.dport == 8443:
                    return "HTTPS-Alt"
                elif tcp_layer.sport == 6881 or tcp_layer.dport == 6881:
                    return "BitTorrent"
                else:
                    return "TCP"
        elif packet.haslayer(scapy.UDP):  # type: ignore
            # Check for common UDP protocols based on ports
            if packet.haslayer(scapy.UDP):  # type: ignore
                udp_layer = packet[scapy.UDP]  # type: ignore
                if udp_layer.sport == 53 or udp_layer.dport == 53:
                    return "DNS"
                elif udp_layer.sport == 67 or udp_layer.dport == 67:
                    return "DHCP-Server"
                elif udp_layer.sport == 68 or udp_layer.dport == 68:
                    return "DHCP-Client"
                elif udp_layer.sport == 69 or udp_layer.dport == 69:
                    return "TFTP"
                elif udp_layer.sport == 123 or udp_layer.dport == 123:
                    return "NTP"
                elif udp_layer.sport == 161 or udp_layer.dport == 161:
                    return "SNMP"
                elif udp_layer.sport == 162 or udp_layer.dport == 162:
                    return "SNMP-Trap"
                elif udp_layer.sport == 514 or udp_layer.dport == 514:
                    return "Syslog"
                elif udp_layer.sport == 6881 or udp_layer.dport == 6881:
                    return "BitTorrent"
                else:
                    return "UDP"
        elif packet.haslayer(scapy.ICMP):  # type: ignore
            return "ICMP"
        elif packet.haslayer(scapy.ARP):  # type: ignore
            return "ARP"
        elif hasattr(scapy, "DNS") and packet.haslayer(scapy.DNS):  # type: ignore
            return "DNS"
        elif hasattr(scapy, "DHCP") and packet.haslayer(scapy.DHCP):  # type: ignore
            return "DHCP"
        elif hasattr(scapy, "BOOTP") and packet.haslayer(scapy.BOOTP):  # type: ignore
            return "BOOTP"
        elif hasattr(scapy, "TFTP") and packet.haslayer(scapy.TFTP):  # type: ignore
            return "TFTP"
        elif hasattr(scapy, "SNMP") and packet.haslayer(scapy.SNMP):  # type: ignore
            return "SNMP"
        elif hasattr(scapy, "NTP") and packet.haslayer(scapy.NTP):  # type: ignore
            return "NTP"
        elif hasattr(scapy, "IGMP") and packet.haslayer(scapy.IGMP):  # type: ignore
            return "IGMP"
        elif hasattr(scapy, "ICMPv6") and packet.haslayer(scapy.ICMPv6):  # type: ignore
            return "ICMPv6"
        elif hasattr(scapy, "DHCPv6") and packet.haslayer(scapy.DHCPv6):  # type: ignore
            return "DHCPv6"
        elif packet.haslayer(scapy.IP):  # type: ignore
            if packet[scapy.IP].proto == 2:
                return "IGMP"
        else:
            return "Other"
    
    def get_payload_info(self, packet):
        """Extract payload information from packet"""
        if packet.haslayer(scapy.Raw):  # type: ignore
            payload = packet[scapy.Raw].load  # type: ignore
            # Try to decode as string, fallback to hex
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                if payload_str.isprintable():
                    return payload_str[:100] + "..." if len(payload_str) > 100 else payload_str
                else:
                    return payload.hex()[:50] + "..."
            except:
                return payload.hex()[:50] + "..."
        return "No payload"
    
    def analyze_packet(self, packet):
        """Analyze a single packet and extract useful information"""
        try:
            # Check if packet is valid
            if packet is None:
                return {
                    'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'length': 0,
                    'protocol': 'Unknown',
                    'src_ip': 'Unknown',
                    'dst_ip': 'Unknown',
                    'src_port': 'N/A',
                    'dst_port': 'N/A',
                    'payload': 'No payload'
                }
            
            packet_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'length': len(packet) if packet else 0,
                'protocol': 'Unknown',
                'src_ip': 'Unknown',
                'dst_ip': 'Unknown',
                'src_port': 'N/A',
                'dst_port': 'N/A',
                'payload': 'No payload'
            }
            # Extract IP information
            if packet.haslayer(scapy.IP):  # type: ignore
                packet_info['src_ip'] = packet[scapy.IP].src  # type: ignore
                packet_info['dst_ip'] = packet[scapy.IP].dst  # type: ignore
                if packet_info['src_ip'] != 'Unknown':
                    self.ip_stats[packet_info['src_ip']] += 1  # type: ignore
                if packet_info['dst_ip'] != 'Unknown':
                    self.ip_stats[packet_info['dst_ip']] += 1  # type: ignore
            # Extract protocol information
            protocol = self.get_protocol_name(packet)
            packet_info['protocol'] = protocol
            self.protocol_stats[protocol] += 1
            # Extract port information
            if packet.haslayer(scapy.TCP):  # type: ignore
                packet_info['src_port'] = packet[scapy.TCP].sport  # type: ignore
                packet_info['dst_port'] = packet[scapy.TCP].dport  # type: ignore
                if str(packet_info['src_port']).isdigit():
                    self.port_stats[str(packet_info['src_port'])] += 1  # type: ignore
                if str(packet_info['dst_port']).isdigit():
                    self.port_stats[str(packet_info['dst_port'])] += 1  # type: ignore
            elif packet.haslayer(scapy.UDP):  # type: ignore
                packet_info['src_port'] = packet[scapy.UDP].sport  # type: ignore
                packet_info['dst_port'] = packet[scapy.UDP].dport  # type: ignore
                if str(packet_info['src_port']).isdigit():
                    self.port_stats[str(packet_info['src_port'])] += 1  # type: ignore
                if str(packet_info['dst_port']).isdigit():
                    self.port_stats[str(packet_info['dst_port'])] += 1  # type: ignore
            # Extract payload
            packet_info['payload'] = self.get_payload_info(packet)
            return packet_info
        except Exception as e:
            print(f"{Fore.RED}[!] Exception in analyze_packet: {e}")
            traceback.print_exc()
            # Return basic packet info even if analysis fails
            return {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'length': len(packet) if packet else 0,
                'protocol': 'Unknown',
                'src_ip': 'Unknown',
                'dst_ip': 'Unknown',
                'src_port': 'N/A',
                'dst_port': 'N/A',
                'payload': 'No payload'
            }
    
    def packet_callback(self, packet):
        """Callback function called for each captured packet"""
        if not self.running:
            return
        try:
            self.packet_count += 1
            packet_info = self.analyze_packet(packet)
            self.captured_packets.append(packet_info)
            # Display packet information
            self.display_packet(packet_info)
            # Keep only last 100 packets in memory
            if len(self.captured_packets) > 100:
                self.captured_packets.pop(0)
        except Exception as e:
            print(f"{Fore.RED}[!] Exception in packet_callback: {e}")
            traceback.print_exc()
            # Continue processing other packets
    
    def display_packet(self, packet_info):
        """Display formatted packet information"""
        # Color coding based on protocol
        protocol_colors = {
            'TCP': Fore.BLUE,
            'UDP': Fore.GREEN,
            'ICMP': Fore.YELLOW,
            'ARP': Fore.MAGENTA,
            'DNS': Fore.CYAN,
            'DHCP': Fore.CYAN,
            'DHCP-Server': Fore.CYAN,
            'DHCP-Client': Fore.CYAN,
            'HTTP': Fore.RED,
            'HTTPS': Fore.RED,
            'HTTP-Alt': Fore.RED,
            'HTTPS-Alt': Fore.RED,
            'FTP': Fore.RED,
            'SSH': Fore.RED,
            'SMTP': Fore.RED,
            'SMTPS': Fore.RED,
            'SMTP-Submission': Fore.RED,
            'POP3': Fore.RED,
            'POP3S': Fore.RED,
            'IMAP': Fore.RED,
            'IMAPS': Fore.RED,
            'TELNET': Fore.RED,
            'RDP': Fore.RED,
            'MySQL': Fore.RED,
            'PostgreSQL': Fore.RED,
            'MSSQL': Fore.RED,
            'Oracle': Fore.RED,
            'Redis': Fore.RED,
            'BitTorrent': Fore.MAGENTA,
            'SNMP': Fore.YELLOW,
            'SNMP-Trap': Fore.YELLOW,
            'NTP': Fore.YELLOW,
            'TFTP': Fore.YELLOW,
            'Syslog': Fore.YELLOW,
            'IGMP': Fore.MAGENTA,
            'ICMPv6': Fore.YELLOW,
            'DHCPv6': Fore.CYAN,
            'Other': Fore.WHITE
        }
        
        color = protocol_colors.get(packet_info['protocol'], Fore.WHITE)
        
        print(f"{color}[{packet_info['timestamp']}] "
              f"Protocol: {packet_info['protocol']} | "
              f"Length: {packet_info['length']} bytes | "
              f"Source: {packet_info['src_ip']}:{packet_info['src_port']} | "
              f"Destination: {packet_info['dst_ip']}:{packet_info['dst_port']}")
        
        if packet_info['payload'] != "No payload":
            print(f"{Style.DIM}    Payload: {packet_info['payload']}")
    
    def display_statistics(self):
        """Display capture statistics"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}CAPTURE STATISTICS")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Protocol statistics
        if self.protocol_stats:
            # Debug: print any None or non-int values
            bad_protocols = [(protocol, count) for protocol, count in self.protocol_stats.items() if not isinstance(count, int) or count is None]
            if bad_protocols:
                print(f"{Fore.RED}[DEBUG] Protocol stats with non-int or None values: {bad_protocols}")
            print(f"\n{Fore.YELLOW}Protocol Distribution:")
            protocol_data = [[protocol, count] for protocol, count in self.protocol_stats.items() if isinstance(count, int) and count is not None]
            print(tabulate(protocol_data, headers=['Protocol', 'Count'], tablefmt='grid'))
        
        # Top IP addresses
        if self.ip_stats:
            # Debug: print any None or non-int values
            bad_ips = [(ip, count) for ip, count in self.ip_stats.items() if not isinstance(count, int) or count is None]
            if bad_ips:
                print(f"{Fore.RED}[DEBUG] IP stats with non-int or None values: {bad_ips}")
            print(f"\n{Fore.YELLOW}Top IP Addresses:")
            # Only show valid IPs (not 'Unknown')
            top_ips = sorted(
                ((ip, count) for ip, count in self.ip_stats.items() if ip != 'Unknown' and isinstance(count, int) and count is not None),
                key=lambda x: x[1], reverse=True)[:10]
            ip_data = [[ip, count] for ip, count in top_ips]
            print(tabulate(ip_data, headers=['IP Address', 'Count'], tablefmt='grid'))
        
        # Top ports
        if self.port_stats:
            # Debug: print any None or non-int values
            bad_ports = [(port, count) for port, count in self.port_stats.items() if not isinstance(count, int) or count is None]
            if bad_ports:
                print(f"{Fore.RED}[DEBUG] Port stats with non-int or None values: {bad_ports}")
            print(f"\n{Fore.YELLOW}Top Ports:")
            # Only show numeric ports (not 'N/A')
            top_ports = sorted(
                ((port, count) for port, count in self.port_stats.items() if port.isdigit() and isinstance(count, int) and count is not None),
                key=lambda x: x[1], reverse=True)[:10]
            port_data = [[port, count] for port, count in top_ports]
            print(tabulate(port_data, headers=['Port', 'Count'], tablefmt='grid'))
        
        print(f"\n{Fore.GREEN}Total packets captured: {self.packet_count}")
    
    def start_capture(self, interface=None, filter_string=None, count=None, timeout=None):
        """Start packet capture"""
        self.running = True
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"{Fore.GREEN}[+] Starting packet capture...")
        if interface:
            print(f"{Fore.GREEN}[+] Interface: {interface}")
        if filter_string:
            print(f"{Fore.GREEN}[+] Filter: {filter_string}")
        if count:
            print(f"{Fore.GREEN}[+] Packet count limit: {count}")
        if timeout:
            print(f"{Fore.GREEN}[+] Timeout: {timeout} seconds")
        print(f"{Fore.GREEN}[+] Press Ctrl+C to stop capture")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Fix: ensure count is always an int for scapy.sniff
        count = count if count is not None else 0
        try:
            # Start sniffing
            scapy.sniff(  # type: ignore
                iface=interface,
                filter=filter_string,
                prn=self.packet_callback,
                count=count,
                timeout=timeout,
                store=0  # Don't store packets in memory (we handle storage ourselves)
            )
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{Fore.RED}[!] Error during capture: {e}")
            traceback.print_exc()
            # Continue to display statistics even if there was an error
        finally:
            self.running = False
            try:
                self.display_statistics()
            except Exception as e:
                print(f"{Fore.RED}[!] Error displaying statistics: {e}")
                print(f"{Fore.GREEN}Total packets captured: {self.packet_count}")

def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer - Capture and analyze network packets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_sniffer.py                    # Capture all packets
  python network_sniffer.py -i eth0            # Capture on specific interface
  python network_sniffer.py -f "tcp port 80"   # Capture only HTTP traffic
  python network_sniffer.py -c 100             # Capture only 100 packets
  python network_sniffer.py -i eth0 -f "udp"   # Capture UDP on eth0
        """
    )
    
    parser.add_argument('-i', '--interface', 
                       help='Network interface to capture on (default: auto-detect)')
    parser.add_argument('-f', '--filter', 
                       help='BPF filter string (e.g., "tcp port 80")')
    parser.add_argument('-c', '--count', type=int, 
                       help='Number of packets to capture (default: unlimited)')
    parser.add_argument('-t', '--timeout', type=int, 
                       help='Timeout in seconds (default: unlimited)')
    parser.add_argument('--list-interfaces', action='store_true',
                       help='List available network interfaces')
    
    args = parser.parse_args()
    
    # List interfaces if requested
    if args.list_interfaces:
        print(f"{Fore.CYAN}Available network interfaces:")
        interfaces = scapy.get_if_list()  # type: ignore
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
        return
    
    # Validate filter if provided
    if args.filter:
        try:
            # Test if the filter is valid by trying to compile it
            # We'll use a simple validation approach
            if not any(keyword in args.filter.lower() for keyword in ['tcp', 'udp', 'icmp', 'arp', 'host', 'port', 'src', 'dst', 'net', 'and', 'or', 'not']):
                raise ValueError("Filter contains no valid BPF keywords")
        except Exception as e:
            print(f"{Fore.RED}[!] Invalid filter: {args.filter}")
            print(f"{Fore.RED}[!] Error: {e}")
            print(f"{Fore.YELLOW}[!] Valid filter examples:")
            print(f"{Fore.YELLOW}    tcp port 80")
            print(f"{Fore.YELLOW}    udp port 53")
            print(f"{Fore.YELLOW}    host 192.168.1.1")
            print(f"{Fore.YELLOW}    src host 192.168.1.1")
            print(f"{Fore.YELLOW}    tcp and port 443")
            return
    
    # Create and start sniffer
    sniffer = NetworkSniffer()
    sniffer.start_capture(
        interface=args.interface,
        filter_string=args.filter,
        count=args.count,
        timeout=args.timeout
    )

if __name__ == "__main__":
    # Check if running with administrator privileges (required for packet capture)
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print(f"{Fore.RED}[!] Warning: This program may require administrator privileges on Windows")
        except:
            pass
    else:  # Unix-like systems
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Warning: This program may require root privileges")
    
    main() 