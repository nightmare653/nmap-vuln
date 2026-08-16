#!/usr/bin/env python3
"""Standalone launcher so the tool runs without installation."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nmapvuln.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
