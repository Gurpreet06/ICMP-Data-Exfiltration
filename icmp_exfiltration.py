#!/usr/bin/env python3
import signal
import sys
import time
from scapy.all import *
from colorama import Fore


def ctrl_c(signum, frame):
    get_colours("\n[*] Exiting the program...", "blue")
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
