#!/usr/bin/python3
import nmap
import sys
import datetime

def scan_network(target_ip):
    nm = nmap.PortScanner()
    print(f"Starting scan of {target_ip} at {datetime.datetime.now()}")

    try:
        nm.scan(target_ip, arguments='-sS -sV -O')
        for host in nm.all_hosts():
            print(f"\nHost: {host}")
            print(f"State: {nm[host].state()}")

            if 'osmatch' in nm[host]:
                for os in nm[host]['osmatch']:
                    print(f"OS Match: {os['name']} ({os['accuracy']}%)")

            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    print(f"Port: {port}\tState: {service['state']}\tService: {service['name']}\tVersion: {service['version']}")
    except Exception as e:
        print(f"Scan failed: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./port_scanner.py <target_ip>")
        sys.exit(1)
    scan_network(sys.argv[1])
