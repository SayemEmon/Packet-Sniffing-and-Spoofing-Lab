#!/usr/bin/env python3

from scapy.all import sniff, send, IP, ICMP

# Function to sniff ICMP packets and spoof a reply
def sniff_and_spoof(pkt):
   if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # ICMP echo request
       print(f"[+] Sniffed ICMP Request from {pkt[IP].src} to {pkt[IP].dst}")


       # Create a spoofed ICMP reply
       spoofed_pkt = IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)


       # Send the spoofed packet
       send(spoofed_pkt, verbose=False)
       print(f"Spoofed ICMP Reply sent to {pkt[IP].src}")


# Get network interface
iface = "br-c5386aec72c5"


print(f"Sniffing on interface {iface}...")
sniff(iface=iface, filter="icmp", prn=sniff_and_spoof, store=False)