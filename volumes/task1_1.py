#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()
pkt = sniff(iface='br-38c8e90cb196', filter='icmp', prn=print_pkt)




