#!/usr/bin/python3
from scapy.all import *
import argparse
import datetime

def analyze_packet(packet):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[{timestamp}] TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} Flags: {flags}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{timestamp}] UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif ICMP in packet:
            icmp_type = packet[ICMP].type
            print(f"[{timestamp}] ICMP {src_ip} -> {dst_ip} Type: {icmp_type}")

def capture_traffic(interface, count):
    print(f"Starting packet capture on {interface}")
    sniff(iface=interface, prn=analyze_packet, count=count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to capture')
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')

    args = parser.parse_args()
    capture_traffic(args.interface, args.count)
