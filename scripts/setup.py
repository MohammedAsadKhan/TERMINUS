#!/usr/bin/env python3
# File name: setup.py
# Author: Team LARP
# Date: 2026-11-09
# Version: 0.1.0
# Purpose: CLI Entrypoint wrapper for Terminus interactive setup wizard.

"""CLI Entrypoint wrapper for Terminus interactive setup wizard."""

from __future__ import annotations

import sys
from pathlib import Path

# Add src/ directory to Python module search path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from terminus.setup import main

if __name__ == "__main__":
    main()
