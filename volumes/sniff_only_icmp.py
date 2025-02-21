#!usr/bin/python
from scapy.all import *
def print_pkt(pkt):


   if pkt[ICMP] is not None:
       if pkt[ICMP].type == 0 or pkt[ICMP].type == 8:
           print("ICMP Packet--->>>>")
           print(f"\t Source: {pkt[IP].src}")
           print(f"\t Destination: {pkt[IP].dst}")


           if pkt[ICMP].type == 0:
               print(f"\t ICMP type: echo - reply")


           if pkt[ICMP].type == 8:
               print(f"\t ICMP type: echo - request")


pkt = sniff(iface='br-38c8e90cb196', filter='icmp', prn=print_pkt)