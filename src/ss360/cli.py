# SPDX-License-Identifier: MIT
"""
Secret Scan 360 - Command Line Interface

Safe defaults:
- ss360 scan <root> --json-out findings.json
- In GitHub Actions, also writes findings.sarif automatically.

Compatibility flags accepted (no-ops today):
- --policy PATH
- --format {text,json,sarif}
"""

from __future__ import annotations

import argparse
import os
import sys
import subprocess
from . import __version__


def main(argv=None):
    argv = argv or sys.argv[1:]
    p = argparse.ArgumentParser(prog="ss360", description="Secret Scan 360")
    p.add_argument("-v", "--version", action="store_true", help="print version and exit")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print version")

    sp = sub.add_parser("scan", help="scan a repo/workspace")
    sp.add_argument("root", nargs="?", default=".", help="path to scan")
    sp.add_argument(
        "--json-out",
        dest="json_out",
        default="findings.json",
        help="where to write JSON results (default: findings.json)",
    )
    # Accept but ignore (compat)
    sp.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="json",
        help="output format hint (compat; no-op)",
    )
    sp.add_argument(
        "--policy",
        dest="policy",
        help="policy file path (compat; no-op)",
    )
    sp.add_argument(
        "--sarif-out",
        dest="sarif_out",
        help="where to write SARIF (default in CI: findings.sarif)",
    )

    args = p.parse_args(argv)
    if args.version or args.cmd == "version":
        print(__version__)
        return 0

    if args.cmd == "scan":
        sarif_out = args.sarif_out
        if not sarif_out and os.getenv("GITHUB_ACTIONS") == "true":
            sarif_out = "findings.sarif"

        cmd = [
            sys.executable,
            "scripts/ci_scan.py",
            "--json-out",
            args.json_out,
            "--root",
            args.root,
        ]
        if sarif_out:
            cmd += ["--sarif-out", sarif_out]
        return subprocess.call(cmd)

    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())