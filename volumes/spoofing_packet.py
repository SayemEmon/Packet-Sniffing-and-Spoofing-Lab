#!/usr/bin/env python3


from scapy.all import IP, ICMP, send


# Define the target and spoofed IPs
target_ip = "10.9.0.5"  # Destination
spoofed_ip = "192.168.1.100"  # Fake Source IP


# Construct IP Header
ip_packet = IP(src=spoofed_ip, dst=target_ip)


# Construct ICMP Packet (ping request)
icmp_packet = ICMP()


# Combine IP and ICMP headers
spoofed_packet = ip_packet / icmp_packet


# Send the spoofed packet
send(spoofed_packet)


print(f"[+] Spoofed ICMP packet sent to {target_ip} from {spoofed_ip}")