#!/usr/bin/env python3
"""
utils/helpers.py — Common Utility Functions

Yeh file contains helper functions jo project ki 
saari files mein use hoti hain:
- Root/sudo check
- Tool availability check
- Logging
- Banner display
- Subprocess execution
- File operations
"""

import os
import sys
import subprocess
from datetime import datetime


def check_root():
    """
    Check if script is running with root/sudo privileges.
    
    hostapd-wpe, aircrack-ng, Bettercap — sabko root chahiye.
    Agar root nahi hai toh main.py exit kar jayega.
    
    Returns:
        bool: True if root, False otherwise
    """
    if os.geteuid() != 0:
        return False
    return True


def check_tools(tools_list):
    """
    Check if required system tools are installed.
    
    Kali Linux mein zyadaatar tools pre-installed hote hain,
    lekin confirm kar lena safe hai.
    
    Args:
        tools_list (list): Tool names to check (e.g., ["aircrack-ng", "hostapd-wpe"])
    
    Returns:
        list: Missing tools (empty list if all present)
    """
    missing = []
    for tool in tools_list:
        # 'which' command se tool ka path check karo
        result = subprocess.run(
            ["which", tool], 
            capture_output=True, 
            text=True
        )
        if result.returncode != 0:
            missing.append(tool)
    return missing


def setup_log_file(config_dir):
    """
    Create log file with timestamp.
    
    Args:
        config_dir (str): Directory for logs
    
    Returns:
        str: Log file path
    """
    os.makedirs(config_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(config_dir, f"ghostpillage_{timestamp}.log")
    return log_file


def log(log_file, message, verbose=False):
    """
    Write timestamped message to log file and optionally print.
    
    Args:
        log_file (str): Path to log file
        message (str): Message to log
        verbose (bool): If True, also print to console
    """
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    
    # Write to file
    try:
        with open(log_file, "a") as f:
            f.write(log_entry + "\n")
    except Exception:
        pass  # Log file write fail — continue
    
    # Print if verbose
    if verbose:
        print(f"  {log_entry}")


def print_banner():
    """
    GhostPillage ASCII banner print karo.
    
    Sirf startup mein show hota hai.
    """
    banner = """
    ╔══════════════════════════════════════════════════╗
    ║               G H O S T P I L L A G E           ║
    ║     GhostAP + WiFiPillage — Combined Offensive  ║
    ║         Wireless Attack Suite v1.0              ║
    ╚══════════════════════════════════════════════════╝
    """
    print(banner)


def run_command(cmd, timeout=None, verbose=False, log_file=None):
    """
    Execute a system command and return output.
    
    hostapd-wpe, aireplay-ng, Bettercap — saare system commands
    hain. Yeh function unhe execute karta hai aur output return karta hai.
    
    Args:
        cmd (str): Command to execute
        timeout (int): Command timeout in seconds (default: no timeout)
        verbose (bool): Print command output
        log_file (str): Optional log file path
    
    Returns:
        dict: {
            "stdout": str,
            "stderr": str,
            "returncode": int,
            "success": bool
        }
    """
    if verbose and log_file:
        log(log_file, f"[CMD] {cmd}", verbose)
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0
        }
        
        if verbose and log_file:
            log(log_file, f"[CMD_OUT] Exit code: {result.returncode}", verbose)
            if result.stdout:
                log(log_file, f"[CMD_STDOUT] {result.stdout[:200]}", verbose)
        
        return output
        
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out",
            "returncode": -1,
            "success": False
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "success": False
        }


def check_interface_mode(interface):
    """
    Check if wireless interface is in monitor mode.
    
    Args:
        interface (str): Interface name (e.g., wlan0)
    
    Returns:
        bool: True if monitor mode is enabled
    """
    cmd = f"iwconfig {interface} 2>/dev/null | grep -i 'Mode:Monitor'"
    result = run_command(cmd)
    return result["success"]


def enable_monitor_mode(interface, log_file=None, verbose=False):
    """
    Enable monitor mode on a wireless interface.
    
    Step-by-step:
    1. Bring interface down
    2. Kill interfering processes (NetworkManager, wpa_supplicant)
    3. Set monitor mode
    4. Bring interface up
    
    Args:
        interface (str): Interface name
        log_file (str): Log file path
        verbose (bool): Verbose output
    
    Returns:
        bool: True if successful
    """
    if log_file:
        log(log_file, f"[*] Enabling monitor mode on {interface}", verbose)
    
    steps = [
        f"ip link set {interface} down",
        f"airmon-ng check kill",
        f"iw dev {interface} set type monitor",
        f"ip link set {interface} up"
    ]
    
    for step in steps:
        result = run_command(step, verbose=verbose, log_file=log_file)
        if not result["success"] and "airmon-ng check kill" not in step:
            # airmon-ng check kill might return non-zero even on success
            if log_file:
                log(log_file, f"[!] Step failed: {step}", verbose)
            return False
    
    # Verify
    time.sleep(1)
    if check_interface_mode(interface):
        if log_file:
            log(log_file, f"[+] Monitor mode enabled on {interface}", verbose)
        return True
    else:
        if log_file:
            log(log_file, f"[!] Failed to enable monitor mode on {interface}", verbose)
        return False


def disable_monitor_mode(interface, log_file=None, verbose=False):
    """
    Disable monitor mode and restore normal operation.
    
    Args:
        interface (str): Interface name
        log_file (str): Log file path
        verbose (bool): Verbose output
    
    Returns:
        bool: True if successful
    """
    if log_file:
        log(log_file, f"[*] Disabling monitor mode on {interface}", verbose)
    
    steps = [
        f"ip link set {interface} down",
        f"iw dev {interface} set type managed",
        f"ip link set {interface} up",
        "systemctl restart NetworkManager"
    ]
    
    for step in steps:
        run_command(step, verbose=verbose, log_file=log_file)
    
    if log_file:
        log(log_file, f"[+] {interface} restored to managed mode", verbose)
    
    return True


def get_wireless_interfaces():
    """
    List available wireless interfaces.
    
    Returns:
        list: Interface names (e.g., ["wlan0", "wlan1"])
    """
    cmd = "iw dev 2>/dev/null | grep Interface | awk '{print $2}'"
    result = run_command(cmd)
    
    if result["success"] and result["stdout"].strip():
        return result["stdout"].strip().split("\n")
    return []


def file_exists(filepath):
    """
    Check if a file exists.
    
    Args:
        filepath (str): Path to file
    
    Returns:
        bool: True if file exists
    """
    return os.path.exists(filepath)


def read_file(filepath):
    """
    Read entire file content.
    
    Args:
        filepath (str): Path to file
    
    Returns:
        str: File content, or empty string if error
    """
    try:
        with open(filepath, "r") as f:
            return f.read()
    except Exception:
        return ""


def write_file(filepath, content):
    """
    Write content to file.
    
    Args:
        filepath (str): Path to file
        content (str): Content to write
    
    Returns:
        bool: True if successful
    """
    try:
        with open(filepath, "w") as f:
            f.write(content)
        return True
    except Exception:
        return False


# Agar directly run kiya jaaye toh banner dikhao
if __name__ == "__main__":
    print_banner()
    print(f"[+] Helper functions loaded successfully")
    print(f"[+] Root: {'Yes' if check_root() else 'No (run with sudo)'}")
    print(f"[+] Wireless interfaces: {get_wireless_interfaces()}")