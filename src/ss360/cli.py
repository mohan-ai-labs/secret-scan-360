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

    # Aggregate subcommand
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

    # Scan subcommand
    scan_parser = org_sub.add_parser("scan", help="scan multiple repositories")
    scan_parser.add_argument(
        "--repos",
        nargs="+",
        required=True,
        help="repository URLs to scan",
    )
    scan_parser.add_argument(
        "--out",
        dest="output_dir",
        default=".artifacts/org",
        help="output directory for scan results (default: .artifacts/org)",
    )
    scan_parser.add_argument(
        "--only-category",
        choices=["actual", "expired", "test", "unknown"],
        help="only include findings of this category in results",
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
        elif args.org_cmd == "scan":
            # Import git operations
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from services.agents.app.core.git_ops import shallow_clone, cleanup

            output_dir = Path(args.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)

            overall_success = True

            for repo_url in args.repos:
                # Extract repo name from URL
                repo_name = repo_url.rstrip("/").split("/")[-1]
                if repo_name.endswith(".git"):
                    repo_name = repo_name[:-4]

                print(f"[org-scan] Scanning {repo_url} -> {repo_name}")

                temp_path = None
                try:
                    # Clone repository
                    temp_path = shallow_clone(repo_url)

                    # Create output directory for this repo
                    repo_output_dir = output_dir / repo_name
                    repo_output_dir.mkdir(parents=True, exist_ok=True)

                    # Prepare scan command
                    scan_cmd = [
                        sys.executable,
                        "scripts/ci_scan.py",
                        "--json-out",
                        str(repo_output_dir / "findings.json"),
                        "--sarif-out",
                        str(repo_output_dir / "findings.sarif"),
                        "--root",
                        temp_path,
                    ]

                    if args.only_category:
                        scan_cmd += ["--only-category", args.only_category]

                    # Run scan
                    result = subprocess.call(scan_cmd)

                    if result != 0:
                        print(f"[org-scan] WARNING: Scan failed for {repo_name}")
                        overall_success = False
                    else:
                        print(f"[org-scan] Successfully scanned {repo_name}")

                    # Copy CODEOWNERS if it exists
                    codeowners_path = Path(temp_path) / "CODEOWNERS"
                    if codeowners_path.exists():
                        import shutil

                        shutil.copy2(codeowners_path, repo_output_dir / "CODEOWNERS")
                        print(f"[org-scan] Copied CODEOWNERS for {repo_name}")

                except Exception as e:
                    print(f"[org-scan] ERROR: Failed to scan {repo_url}: {e}")
                    overall_success = False

                finally:
                    # Clean up temporary directory
                    if temp_path:
                        cleanup(temp_path)

            return 0 if overall_success else 1

    p.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
