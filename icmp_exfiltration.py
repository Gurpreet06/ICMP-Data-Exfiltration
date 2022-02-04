#!/usr/bin/env python3
import signal
import sys
import time
from scapy.all import *
from colorama import Fore


def ctrl_c(signum, frame):
    get_colours("\n\n[*] Exiting the program...", "blue")
    time.sleep(1)
    exit(1)


signal.signal(signal.SIGINT, ctrl_c)


# Colours
def get_colours(text, color):
    if color == "blue":
        blue_color = Fore.BLUE + text
        print(blue_color)
    elif color == "red":
        red_color = Fore.RED + text
        print(red_color)


def data_parser(packet_info):
    if packet_info.haslayer(ICMP):
        if packet_info[ICMP].type == 8:
            byte_data = packet_info['ICMP'].load[-4:].decode('utf-8')
            print(byte_data, flush=True, end='')


if len(sys.argv) != 2:
    print(f"\n{Fore.RED + '[!]'}", f"{Fore.WHITE + f'Usage {sys.argv[0]} <Interface-Name>'}")
else:
    try:
        get_colours("\n[*] Listening for any incoming connections...", 'blue')
        print(Fore.WHITE)  # To avoid leaving the terminal with colors.
        sniff(iface=f'{sys.argv[1]}', prn=data_parser)
    except PermissionError:
        get_colours("\n[!] Run program with admin privilege", 'red')
    except OSError:
        get_colours("\n[!] No such interface found", 'red')
