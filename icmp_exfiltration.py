#!/usr/bin/env python3
from scapy.all import *
from colorama import Fore
import signal
import subprocess
import sys
import time


def ctrl_c(signum, frame):
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
          f"{Fore.BLUE + '  Exiting the program...'}")
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
            byte_data = packet_info['ICMP'].load[-4:].decode('utf-8', errors="backslashreplace")
            a = open(f'{sys.argv[2]}.txt', 'a')
            a.write(byte_data)
            a.close()
            print(byte_data, flush=True, end='')


if len(sys.argv) != 3:
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
          f"{Fore.YELLOW + f' Usage {sys.argv[0]} <Interface-Name> <File-name to save data>'}")
else:
    check_interface = subprocess.check_output("ip a | grep '%s' | awk '{print $2}' | grep"
                                              " '%s' | awk '{print $1}' FS=':'" % (
                                                  sys.argv[1], sys.argv[1]),
                                              shell=True).decode().strip()
    if sys.argv[1] != check_interface:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + '  No such interface'}")
        print(Fore.WHITE)
        exit()
    elif os.getuid() != 0:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + ' Run this script with administrator privileges.'}")
        exit()
    else:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
              f"{Fore.BLUE + '  Listening for any incoming connections...'}")
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
              f"{Fore.BLUE + '  Saving data to file'}")
        print(Fore.WHITE)  # To avoid leaving the terminal with colors.
        sniff(iface=f'{sys.argv[1]}', prn=data_parser)
