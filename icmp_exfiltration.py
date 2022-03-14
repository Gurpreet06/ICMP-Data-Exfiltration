#!/usr/bin/env python3
import signal
import sys
import time
from scapy.all import *
from colorama import Fore


def ctrl_c(signum, frame):
    get_colours("\n\n[*] Exiting the program...\n", "blue")
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
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
          f"{Fore.YELLOW + f' Usage {sys.argv[0]} <Interface-Name>'}")
else:
    try:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
                  f"{Fore.BLUE + '  Listening for any incoming connections...'}")
        print(Fore.WHITE)  # To avoid leaving the terminal with colors.
        try:
            sniff(iface=f'{sys.argv[1]}', prn=data_parser)
        except ModuleNotFoundError:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
                  f"{Fore.BLUE + ' Scapy not found installed on the system'}")
            print(f"\n{Fore.BLUE + '┃'}  {Fore.YELLOW + ' pip3 install scapy'}")
    except PermissionError:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + ' Run this script with administrator privileges.'}")
        print(Fore.WHITE)
    except OSError:
        get_colours("\n[!] No such interface found\n", 'red')
        print(Fore.WHITE)
