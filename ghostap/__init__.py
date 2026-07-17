#!/usr/bin/env python3
"""
ghostap/__init__.py — GhostAP Package Initializer

Yeh file ghostap folder ko Python package banati hai.
Iske bina Python "ghostap.hostapd_config" ya "ghostap.deauth"
import nahi kar payega.

Package Structure:
ghostap/
├── __init__.py         ← Yeh file
├── hostapd_config.py   ← Rogue AP config generator
└── deauth.py           ← Deauthentication engine
"""

from .hostapd_config import HostapdConfig
from .deauth import DeauthEngine

__all__ = ['HostapdConfig', 'DeauthEngine']

# Package metadata
__version__ = '1.0.0'
__description__ = 'GhostAP - Rogue Enterprise Access Point Module'