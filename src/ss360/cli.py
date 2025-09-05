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
from pathlib import Path
from . import __version__


def main(argv=None):
    argv = argv or sys.argv[1:]
    p = argparse.ArgumentParser(prog="ss360", description="Secret Scan 360")
    p.add_argument(
        "-v", "--version", action="store_true", help="print version and exit"
    )

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
    sp.add_argument(
        "--only-category",
        choices=["actual", "expired", "test", "unknown"],
        help="only include findings of this category in results",
    )

    # Add org command with subcommands
    org_parser = sub.add_parser("org", help="organization-level operations")
    org_sub = org_parser.add_subparsers(dest="org_cmd")

    agg_parser = org_sub.add_parser("aggregate", help="aggregate SARIF across repos")
    agg_parser.add_argument(
        "--in",
        dest="input_dir",
        default=".artifacts/org",
        help="input directory containing repo SARIF files (default: .artifacts/org)",
    )
    agg_parser.add_argument(
        "--out",
        dest="output_dir",
        default=".artifacts",
        help="output directory for summary files (default: .artifacts)",
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
        if args.only_category:
            cmd += ["--only-category", args.only_category]
        return subprocess.call(cmd)

    if args.cmd == "org":
        if args.org_cmd == "aggregate":
            # Run the SARIF aggregator directly
            tools_dir = Path(__file__).parent.parent.parent / "tools"
            cmd = [
                sys.executable,
                str(tools_dir / "sarif_aggregate.py"),
                "--in",
                args.input_dir,
                "--out",
                args.output_dir,
            ]
            return subprocess.call(cmd)

    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
