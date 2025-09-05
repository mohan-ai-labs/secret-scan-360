#!/usr/bin/env python3
"""
Repo secret scan for CI.

Examples:
  python scripts/ci_scan.py \
    --detectors services/agents/app/config/detectors.yaml \
    --include "**/*" \
    --exclude "**/.git/**" "**/.venv/**" "**/node_modules/**" "**/dist/**" "**/build/**" \
    --min-match-len 8 \
    --max-findings 0 \
    --root . \
    --out findings.json \
    --sarif-out findings.sarif
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

# Ensure repository root is on the Python path when executed as a script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ss360.scanner import Scanner  # noqa: E402


# Use recursive globs so top-level dirs are excluded too
DEFAULT_EXCLUDES = [
    "**/.git/**",
    "**/.svn/**",
    "**/.hg/**",
    "**/.venv/**",
    "**/venv/**",
    "**/node_modules/**",
    "**/dist/**",
    "**/build/**",
    "**/.pytest_cache/**",
    "**/__pycache__/**",
    # Project content we don't want to scan for secrets in CI
    "docs/**",
    "**/docs/**",
    "tests/**",
    "**/tests/**",
    "detectors/**",
    "**/detectors/**",
    # Config and packaging junk
    "**/services/agents/app/config/detectors.yaml",
    "src/secret_scan_360.egg-info/**",
    "**/*.egg-info/**",
]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Secret scan CI gate")
    # Primary options
    p.add_argument("--root", default=".", help="Root path to scan (default: .)")
    p.add_argument(
        "--config",
        dest="config",
        default="services/agents/app/config/detectors.yaml",
        help="Detectors YAML config",
    )
    # Aliases used by older steps/workflows
    p.add_argument(
        "--detectors",
        dest="detectors",
        help="Alias for --config (detectors YAML path)",
    )
    p.add_argument(
        "--include",
        nargs="*",
        default=["**/*"],
        help="Glob(s) to include (space-separated)",
    )
    p.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Glob(s) to exclude in addition to defaults (space-separated)",
    )
    p.add_argument(
        "--min-match-len",
        type=int,
        default=0,
        help="Minimum length for the 'match' string to keep a finding (default: 0)",
    )
    # Allow environment to override the default max_findings if desired
    default_max = int(os.getenv("SS360_CI_MAX_FINDINGS", "0"))
    p.add_argument(
        "--max-findings",
        type=int,
        default=default_max,
        help="Fail if total findings exceed this number (default: 0 means fail on any finding)",
    )
    p.add_argument(
        "--json-out",
        dest="json_out",
        help="Write JSON report to this path",
    )
    # Alias used by workflow snippet
    p.add_argument(
        "--out",
        dest="out",
        help="Alias for --json-out",
    )
    # New: write SARIF to a path for GitHub Code Scanning upload
    p.add_argument(
        "--sarif-out",
        dest="sarif_out",
        help="Write SARIF report to this path",
    )
    return p.parse_args()


def filter_findings(
    findings: List[Dict[str, Any]],
    min_match_len: int,
) -> List[Dict[str, Any]]:
    if min_match_len <= 0:
        return findings
    keep: List[Dict[str, Any]] = []
    for f in findings:
        match_val = f.get("match") or ""
        if isinstance(match_val, str) and len(match_val) >= min_match_len:
            keep.append(f)
        else:
            # Some detectors may not set 'match'; keep conservative behavior:
            if not match_val and min_match_len == 0:
                keep.append(f)
    return keep


def drop_ci_noise(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Remove findings originating from docs/, tests/, or detectors/ trees.
    This is a safety net to keep CI gating focused on real source code,
    even if glob matching misses on some platforms/paths.
    """
    noise_markers = ("/docs/", "/tests/", "/detectors/")
    out: List[Dict[str, Any]] = []
    for f in findings:
        p = str(f.get("path") or "")
        p_norm = p.replace("\\", "/")  # normalize for Windows, just in case
        if any(marker in p_norm for marker in noise_markers):
            continue
        out.append(f)
    return out


def _to_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a minimal SARIF v2.1.0 document from the report.
    """
    findings = report.get("findings", []) or []
    root = str(report.get("root", ""))

    # Collect rules by 'kind'
    rule_ids = {}
    rules = []
    for f in findings:
        k = f.get("kind", "Unknown")
        if k not in rule_ids:
            rule_ids[k] = len(rules)
            rules.append(
                {
                    "id": k,
                    "name": k,
                    "shortDescription": {"text": f"SS360 rule: {k}"},
                    "fullDescription": {"text": f"Findings of kind {k}"},
                    "helpUri": "https://github.com/mohan-ai-labs/secret-scan-360",
                }
            )

    results = []
    for f in findings:
        k = f.get("kind", "Unknown")
        ridx = rule_ids.get(k, 0)
        path = str(f.get("path", ""))
        line = int(f.get("line") or 1)
        reason = f.get("reason") or k
        # Normalize path to be repo-relative if possible
        try:
            p_rel = str(Path(path).resolve().relative_to(Path(root).resolve()))
        except Exception:
            p_rel = path
        level = "error" if bool(f.get("is_secret", True)) else "warning"
        results.append(
            {
                "ruleId": k,
                "ruleIndex": ridx,
                "level": level,
                "message": {"text": reason},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": p_rel},
                            "region": {"startLine": max(1, line)},
                        }
                    }
                ],
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SS360",
                        "informationUri": "https://github.com/mohan-ai-labs/secret-scan-360",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif


def main() -> int:
    args = parse_args()

    config_path = args.detectors or args.config
    root = Path(args.root).resolve()

    if not root.exists():
        print(f"[ci-scan] Root path not found: {root}", file=sys.stderr)
        return 2

    if not Path(config_path).exists():
        print(f"[ci-scan] Config not found: {config_path}", file=sys.stderr)
        return 2

    scanner = Scanner.from_config(config_path)
    exclude_globs = DEFAULT_EXCLUDES + (args.exclude or [])
    findings = scanner.scan_paths(
        [root],
        include_globs=args.include,
        exclude_globs=exclude_globs,
        max_bytes=1_000_000,
    )
    findings = filter_findings(findings, args.min_match_len)
    findings = drop_ci_noise(findings)  # final CI-focused filter

    report = {
        "root": str(root),
        "config": str(Path(config_path).resolve()),
        "total": len(findings),
        "findings": findings,
    }

    json_out = args.out or args.json_out
    if json_out:
        Path(json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(json_out).write_text(json.dumps(report, indent=2))
        print(f"[ci-scan] Wrote report: {json_out}")

    # New: write SARIF (before gating) if requested
    if args.sarif_out:
        sarif = _to_sarif(report)
        sarif_path = Path(args.sarif_out)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(sarif, indent=2))
        print(f"[ci-scan] Wrote SARIF: {sarif_path}")

    print(f"[ci-scan] total findings: {report['total']}")
    if args.max_findings is not None and report["total"] > int(args.max_findings):
        print(
            f"[ci-scan] FAIL: findings ({report['total']}) > max_findings ({args.max_findings})",
            file=sys.stderr,
        )
        # Print a short summary to make triage easier in CI logs
        for f in report["findings"][:10]:
            path = f.get("path", "<unknown>")
            line = f.get("line", "?")
            kind = f.get("kind", f.get("id", "<kind?>"))
            reason = f.get("reason", f.get("title", ""))
            print(f"[ci-scan] finding: {path}:{line} kind={kind} reason={reason}", file=sys.stderr)
        return 1

    print("[ci-scan] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())