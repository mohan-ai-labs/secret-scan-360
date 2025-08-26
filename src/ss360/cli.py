# SPDX-License-Identifier: MIT
import argparse
import sys
import subprocess

from . import __version__


def main(argv=None):
    argv = argv or sys.argv[1:]
    p = argparse.ArgumentParser(prog="ss360", description="Secret Scan 360")
    p.add_argument("--version", action="store_true", help="print version and exit")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("scan", help="scan a repo/workspace")
    sp.add_argument("root", nargs="?", default=".", help="path to scan")
    sp.add_argument(
        "--json-out",
        dest="json_out",
        default="findings.json",
        help="where to write JSON results (default: findings.json)",
    )

    args = p.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    if args.cmd == "scan":
        cmd = [sys.executable, "scripts/ci_scan.py", "--json-out", args.json_out, args.root]
        return subprocess.call(cmd)

    p.print_help()
    return 1
