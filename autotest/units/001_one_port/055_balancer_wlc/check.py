#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from scapy.all import *

def dist(packets):
    d = {}
    for packet in packets:
        dst = packet.getlayer(IPv6).dst
        if dst not in d:
            d[dst] = 0
        d[dst] += 1
    return d

def dist_cmd():
    if len(sys.argv) < 3:
        print("Provide file name.")
        exit(1)
    packets = rdpcap(sys.argv[2])
    print(dist(packets))
    exit(0)

def main():
    if len(sys.argv) < 2:
        print("Provide command.")
        exit(1)
    if sys.argv[1] == "dist":
        dist_cmd()
    print("Command not found.")
    exit(1)

if __name__ == "__main__":
    main()

