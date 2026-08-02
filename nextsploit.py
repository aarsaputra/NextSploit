#!/usr/bin/env python3
"""
NextSploit — Next.js Security Auditing & Vulnerability Discovery Framework.
Entry point forwarding to nextsploit/cli.py.
"""

import sys
import os

# Ensure package root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nextsploit.cli import main

if __name__ == "__main__":
    main()
