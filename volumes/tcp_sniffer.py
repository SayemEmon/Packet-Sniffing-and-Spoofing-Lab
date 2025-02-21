#!/usr/bin/python

from scapy.all import *
  
def print_pkt(pkt):
   if pkt[TCP] is not None:
       print('TCP Packet=======>>>')
       print(f"\t Source: {pkt[IP].src}")
       print(f"\t Destination: {pkt[IP].dst}")
       print(f"\t TCP Source Port: {pkt[IP].sport}")
       print(f"\t TCP Destination Port: {pkt[IP].dport}")

pkt = sniff(iface='br-7f023609d674', filter='tcp port 23 and src host 10.9.0.5', prn=print_pkt)