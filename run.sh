#!/bin/bash
# GhostPillage — Easy Run Script
# Usage: ./run.sh --interface wlan0 --ssid "Target-SSID" --mode all

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔═══════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     GhostPillage - Easy Launcher     ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════╝${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[!] This script must be run as root${NC}"
   echo "    sudo ./run.sh [options]"
   exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found${NC}"
    exit 1
fi

# Install dependencies if needed
if [[ ! -f "requirements.installed" ]]; then
    echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
    pip3 install -r requirements.txt 2>/dev/null
    touch requirements.installed
    echo -e "${GREEN}[+] Dependencies installed${NC}"
fi

# Enable monitor mode if requested
if [[ "$1" == "--auto-monitor" ]]; then
    shift
    echo -e "${YELLOW}[*] Enabling monitor mode...${NC}"
    iface="${1:-wlan0}"
    airmon-ng check kill 2>/dev/null
    ip link set $iface down
    iw dev $iface set type monitor
    ip link set $iface up
    echo -e "${GREEN}[+] Monitor mode enabled on $iface${NC}"
fi

# Run GhostPillage
echo -e "${GREEN}[+] Starting GhostPillage...${NC}\n"
python3 main.py "$@"

# Capture exit code
EXIT_CODE=$?

# Disable monitor mode if auto-enabled
if [[ "$AUTO_MONITOR" == "true" ]]; then
    echo -e "${YELLOW}[*] Disabling monitor mode...${NC}"
    ip link set $iface down
    iw dev $iface set type managed
    ip link set $iface up
    systemctl restart NetworkManager 2>/dev/null
fi

echo -e "\n${GREEN}[+] GhostPillage finished (exit code: $EXIT_CODE)${NC}"
exit $EXIT_CODE