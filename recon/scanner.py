#!/usr/bin/env python3
"""
recon/scanner.py — WiFi Environment Scanner

Yeh module target WiFi network ke baare mein information collect karta hai:
- Available networks (SSID, BSSID, channel, encryption)
- Connected clients (MAC addresses, signal strength)
- Enterprise vs Personal encryption detection

Phase 1 of GhostPillage attack chain.
"""

import os
import re
import time
import csv
import subprocess
from utils.helpers import log, run_command


class WiFiScanner:
    """
    WiFi environment scanner.
    
    airodump-ng use karta hai networks aur clients ko discover karne ke liye.
    """
    
    def __init__(self, interface, config_dir, verbose=False):
        """
        Args:
            interface (str): WiFi interface in monitor mode
            config_dir (str): Directory for saving scan results
            verbose (bool): Verbose output
        """
        self.interface = interface
        self.config_dir = os.path.join(config_dir, "recon")
        self.verbose = verbose
        self.log_file = os.path.join(config_dir, "ghostpillage.log")
        
        # Create recon directory
        os.makedirs(self.config_dir, exist_ok=True)
        
        log(self.log_file, "[*] WiFiScanner initialized", self.verbose)
    
    
    def scan_environment(self, target_ssid=None, timeout=30):
        """
        Main scan method — WiFi environment scan karta hai.
        
        airodump-ng use karta hai:
        1. Saare networks dikhta hai
        2. Har network ke clients dikhta hai
        3. Target SSID ko filter karta hai (agar diya ho)
        
        Args:
            target_ssid (str): Optional — specific SSID search karega
            timeout (int): Scan duration in seconds (default: 30)
        
        Returns:
            dict: Target network info {
                "ssid": str,
                "bssid": str,
                "channel": int,
                "encryption": str,
                "clients": int,
                "signal": str,
                "enterprise": bool,
                "all_networks": list,
                "client_list": list
            }
            Returns empty dict if target not found.
        """
        log(self.log_file, f"[*] Starting scan on {self.interface} for {timeout}s", self.verbose)
        print(f"[*] Scanning WiFi environment for {timeout} seconds...")
        
        # Output file prefix
        output_prefix = os.path.join(self.config_dir, "scan")
        
        # Run airodump-ng in background
        # -w: output file prefix (creates .csv, .kismet, .cap files)
        # --output-format csv: CSV format for easy parsing
        cmd = f"timeout {timeout} airodump-ng {self.interface} -w {output_prefix} --output-format csv 2>/dev/null"
        
        result = run_command(cmd, timeout=timeout + 5, verbose=self.verbose, log_file=self.log_file)
        
        # Parse the CSV output
        csv_file = f"{output_prefix}-01.csv"
        if not os.path.exists(csv_file):
            log(self.log_file, "[!] Scan CSV file not found", self.verbose)
            print("[!] No scan results generated. Check interface monitor mode.")
            return self._empty_result(target_ssid)
        
        # Parse networks from CSV
        networks, clients = self._parse_airodump_csv(csv_file)
        
        log(self.log_file, f"[+] Found {len(networks)} networks, {len(clients)} clients", self.verbose)
        print(f"[+] Scan complete: {len(networks)} networks found")
        
        # If target SSID specified, find it
        if target_ssid:
            target_info = self._find_target(networks, clients, target_ssid)
            if target_info:
                log(self.log_file, f"[+] Target '{target_ssid}' found", self.verbose)
                print(f"[+] Target network '{target_ssid}' found!")
                return target_info
            else:
                log(self.log_file, f"[!] Target '{target_ssid}' not in scan results", self.verbose)
                print(f"[!] Target SSID '{target_ssid}' not found in scan")
                return self._empty_result(target_ssid)
        
        # Return all networks if no target specified
        return {
            "ssid": target_ssid or "ALL",
            "bssid": None,
            "channel": None,
            "encryption": None,
            "clients": len(clients),
            "signal": None,
            "enterprise": False,
            "all_networks": networks,
            "client_list": clients,
            "found": False
        }
    
    
    def _parse_airodump_csv(self, csv_file):
        """
        Parse airodump-ng CSV output file.
        
        airodump-ng CSV format:
        - First section: Networks (BSSID, First time seen, Last time seen, channel, Speed, Privacy, ...)
        - "Station MAC" separator line
        - Second section: Clients (Station MAC, First time seen, Last time seen, Power, ...)
        
        Args:
            csv_file (str): Path to CSV file
        
        Returns:
            tuple: (list of networks dict, list of clients dict)
        """
        networks = []
        clients = []
        in_stations_section = False  # True jab client section start ho
        
        try:
            with open(csv_file, "r") as f:
                reader = csv.reader(f)
                for row in reader:
                    # Skip empty rows
                    if not row or len(row) < 2:
                        continue
                    
                    # Check for station section separator
                    if "Station MAC" in row[0] or "BSSID" in row[0] and "First time seen" in row[0]:
                        # Check if this looks like a station header
                        if "Station MAC" in str(row):
                            in_stations_section = True
                            continue
                    
                    # Remove BOM character if present
                    first_col = row[0].replace('\ufeff', '').strip()
                    
                    if not in_stations_section:
                        # Network section
                        if len(row) >= 14 and first_col and first_col != "BSSID":
                            network = self._parse_network_row(row)
                            if network:
                                networks.append(network)
                    else:
                        # Client section
                        if len(row) >= 6 and first_col and first_col != "Station MAC":
                            client = self._parse_client_row(row)
                            if client:
                                clients.append(client)
                                
        except Exception as e:
            log(self.log_file, f"[!] Error parsing CSV: {e}", self.verbose)
        
        return networks, clients
    
    
    def _parse_network_row(self, row):
        """
        Parse a single network row from airodump-ng CSV.
        
        CSV columns (index):
        0: BSSID
        1: First time seen
        2: Last time seen
        3: Channel
        4: Speed
        5: Privacy (encryption)
        6: Cipher
        7: Authentication
        8: Power (signal)
        9: Beacon count
        10: IV count
        11: LAN IP
        12: ID-length
        13: ESSID (SSID)
        
        Args:
            row (list): CSV row
        
        Returns:
            dict: Network information
        """
        try:
            bssid = row[0].strip()
            channel = row[3].strip()
            encryption_raw = row[5].strip()
            signal = row[8].strip()
            ssid = row[13].strip() if len(row) > 13 else ""
            
            # Skip broadcast SSID (hidden networks)
            if not ssid or ssid == "":
                return None
            
            # Detect if enterprise (WPA2-Enterprise contains "WPA2" + "EAP" or "WPA3" + "SAE")
            is_enterprise = False
            encryption_type = "Unknown"
            
            if "WPA2" in encryption_raw and "EAP" in encryption_raw:
                is_enterprise = True
                encryption_type = "WPA2-Enterprise"
            elif "WPA3" in encryption_raw and "SAE" in encryption_raw:
                encryption_type = "WPA3-SAE"
            elif "WPA2" in encryption_raw:
                encryption_type = "WPA2-PSK"
            elif "WPA" in encryption_raw:
                encryption_type = "WPA-PSK"
            elif "OPN" in encryption_raw:
                encryption_type = "Open"
            
            return {
                "ssid": ssid,
                "bssid": bssid,
                "channel": int(channel) if channel.isdigit() else None,
                "encryption": encryption_type,
                "enterprise": is_enterprise,
                "signal": signal,
                "encryption_raw": encryption_raw
            }
            
        except Exception as e:
            log(self.log_file, f"[!] Error parsing network row: {e}", self.verbose)
            return None
    
    
    def _parse_client_row(self, row):
        """
        Parse a single client row from airodump-ng CSV.
        
        CSV columns (index):
        0: Station MAC
        1: First time seen
        2: Last time seen
        3: Power
        4: Packets
        5: BSSID (associated AP)
        6: Probed ESSIDs
        
        Args:
            row (list): CSV row
        
        Returns:
            dict: Client information
        """
        try:
            mac = row[0].strip()
            signal = row[3].strip()
            associated_bssid = row[5].strip() if len(row) > 5 else ""
            probed_ssids = row[6].strip() if len(row) > 6 else ""
            
            return {
                "mac": mac,
                "signal": signal,
                "associated_bssid": associated_bssid,
                "probed_ssids": probed_ssids
            }
            
        except Exception as e:
            log(self.log_file, f"[!] Error parsing client row: {e}", self.verbose)
            return None
    
    
    def _find_target(self, networks, clients, target_ssid):
        """
        Find target SSID in scanned networks list.
        
        Args:
            networks (list): List of network dicts
            clients (list): List of client dicts
            target_ssid (str): Target SSID to find
        
        Returns:
            dict: Target network info with client list
        """
        target_ssid_lower = target_ssid.lower()
        
        for net in networks:
            if net["ssid"].lower() == target_ssid_lower:
                # Get clients associated with this network
                target_clients = []
                for client in clients:
                    if client["associated_bssid"] == net["bssid"]:
                        target_clients.append(client)
                
                return {
                    "ssid": net["ssid"],
                    "bssid": net["bssid"],
                    "channel": net["channel"],
                    "encryption": net["encryption"],
                    "enterprise": net["enterprise"],
                    "signal": net["signal"],
                    "clients": len(target_clients),
                    "client_list": target_clients,
                    "all_networks": networks,
                    "found": True
                }
        
        return None
    
    
    def _empty_result(self, target_ssid):
        """
        Return empty result structure.
        
        Args:
            target_ssid (str): Target SSID
        
        Returns:
            dict: Empty result
        """
        return {
            "ssid": target_ssid,
            "bssid": None,
            "channel": None,
            "encryption": None,
            "clients": 0,
            "signal": None,
            "enterprise": False,
            "all_networks": [],
            "client_list": [],
            "found": False
        }
    
    
    def display_networks(self, networks, limit=20):
        """
        Print scanned networks in formatted table.
        
        Args:
            networks (list): List of network dicts
            limit (int): Max networks to display
        """
        if not networks:
            print("[!] No networks found.")
            return
        
        print("\n" + "-"*80)
        print(f"{'SSID':30s} {'BSSID':18s} {'CH':4s} {'ENC':18s} {'SIG':6s}")
        print("-"*80)
        
        for net in networks[:limit]:
            ssid = net["ssid"][:28] + ".." if len(net["ssid"]) > 28 else net["ssid"]
            bssid = net["bssid"] or "N/A"
            channel = str(net["channel"]) if net["channel"] else "?"
            enc = net["encryption"] or "?"
            signal = net["signal"] or "?"
            
            # Mark enterprise networks
            if net["enterprise"]:
                enc = enc + "★"
            
            print(f"{ssid:30s} {bssid:18s} {channel:4s} {enc:18s} {signal:6s}")
        
        if len(networks) > limit:
            print(f"\n... and {len(networks) - limit} more networks")
        
        print("-"*80)
    
    
    def display_clients(self, clients, limit=20):
        """
        Print discovered clients in formatted table.
        
        Args:
            clients (list): List of client dicts
            limit (int): Max clients to display
        """
        if not clients:
            print("[!] No clients found.")
            return
        
        print("\n" + "-"*60)
        print(f"{'MAC Address':18s} {'Signal':6s} {'Associated AP':18s}")
        print("-"*60)
        
        for client in clients[:limit]:
            mac = client["mac"]
            signal = client["signal"]
            ap = client["associated_bssid"][:17] if client["associated_bssid"] else "Not associated"
            
            print(f"{mac:18s} {signal:6s} {ap:18s}")
        
        if len(clients) > limit:
            print(f"\n... and {len(clients) - limit} more clients")
        
        print("-"*60)


# Direct execution test
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <interface> [ssid]")
        sys.exit(1)
    
    interface = sys.argv[1]
    ssid = sys.argv[2] if len(sys.argv) > 2 else None
    
    scanner = WiFiScanner(interface, "/tmp/test_scan", verbose=True)
    results = scanner.scan_environment(ssid, timeout=15)
    
    if results.get("all_networks"):
        scanner.display_networks(results["all_networks"])
    if results.get("client_list"):
        scanner.display_clients(results["client_list"])