# SPDX-License-Identifier: MIT
"""
Secret Scan 360 - Command Line Interface

Adds:
- ss360 scan --format {text,json,sarif} --policy path --autofix {plan|apply}
- --sarif-out path (optional; auto-writes to findings.sarif on GitHub Actions)
- --i-know-what-im-doing required for apply
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import __version__


def handle_scan_command(args) -> int:
    # Always produce findings.json; also produce SARIF in CI by default
    json_out = args.json_out or "findings.json"
    sarif_out = args.sarif_out
    if not sarif_out and os.getenv("GITHUB_ACTIONS") == "true":
        sarif_out = "findings.sarif"

    cmd = [sys.executable, "scripts/ci_scan.py", "--json-out", json_out, "--root", args.root]
    if sarif_out:
        cmd += ["--sarif-out", sarif_out]

    rc = subprocess.call(cmd)
    # If autofix requested, try to plan/apply based on findings.json
    if args.autofix:
        try:
            from .autofix.planner import AutofixPlanner, format_plan_for_display
        except Exception as e:
            print(f"[ss360] Autofix unavailable: {e}", file=sys.stderr)
            return rc or 0

        data = {}
        try:
            data = json.loads(Path(json_out).read_text())
        except Exception as e:
            print(f"[ss360] Could not read {json_out}: {e}", file=sys.stderr)
            return rc or 0

        findings = data.get("findings", [])
        planner = AutofixPlanner(confirmed_only=True, risk_threshold=int(os.getenv("SS360_RISK_THRESHOLD", "70")))
        plan = planner.plan(findings)
        print(format_plan_for_display(plan))
        if args.autofix == "apply":
            if not args.i_know_what_im_doing:
                print("[ss360] Refusing to apply without --i-know-what-im-doing", file=sys.stderr)
                return 2
            from .autofix.apply import apply_plan  # lazy import
            result = apply_plan(plan, repo_path=".", dry_run=False, i_know_what_im_doing=True)
            print(f"[ss360] apply result: {result}")
    return rc


def main(argv=None):
    argv = argv or sys.argv[1:]
    p = argparse.ArgumentParser(prog="ss360", description="Secret Scan 360")
    p.add_argument("-v", "--version", action="store_true", help="print version and exit")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("version", help="print version")

    sp = sub.add_parser("scan", help="scan a repo/workspace")
    sp.add_argument("root", nargs="?", default=".", help="path to scan")
    sp.add_argument("--json-out", dest="json_out", default="findings.json", help="where to write JSON (default: findings.json)")
    sp.add_argument("--format", choices=["text", "json", "sarif"], default="json", help="output format hint")
    sp.add_argument("--sarif-out", dest="sarif_out", help="where to write SARIF (default in CI: findings.sarif)")
    sp.add_argument("--policy", dest="policy", help="policy file path (unused in minimal CI run)")
    sp.add_argument("--autofix", choices=["plan", "apply"], help="generate or apply autofix plan")
    sp.add_argument("--i-know-what-im-doing", dest="i_know_what_im_doing", action="store_true", help="required for apply")

    args = p.parse_args(argv)
    if args.version or args.cmd == "version":
        print(__version__)
        return 0
    if args.cmd == "scan":
        return handle_scan_command(args)
    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())