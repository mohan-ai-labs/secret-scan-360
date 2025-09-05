#!/usr/bin/env python3
"""
Allow running ss360 as a module: python -m ss360
"""

from ss360.cli import main

if __name__ == "__main__":
    raise SystemExit(main())