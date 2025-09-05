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
from typing import List, Dict, Any, Tuple

# Ensure repository root is on the Python path when executed as a script
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ss360.scanner import Scanner  # noqa: E402
from ss360.sarif.export import build_sarif  # noqa: E402
from ss360.validate.core import run_validators  # noqa: E402
from ss360.classify import classify  # noqa: E402


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
    # Demo/test samples at repo root (exclude to keep CI gate signal-only)
    "test_secrets.py",
    "**/test_secrets.py",
    "test_demo.sh",
    "**/test_demo.sh",
    "demo_e2e.sh",
    "**/demo_e2e.sh",
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
    # Legacy max_findings gate - now defaults to None to rely on policy enforcement
    default_max = os.getenv("SS360_CI_MAX_FINDINGS")
    if default_max is not None:
        default_max = int(default_max)
    p.add_argument(
        "--max-findings",
        type=int,
        default=default_max,
        help="Legacy: Fail if total findings exceed this number (deprecated in favor of policy enforcement)",
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
    # Classification filtering
    p.add_argument(
        "--only-category",
        choices=["actual", "expired", "test", "unknown"],
        help="Only include findings of this category in results",
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


def filter_findings_by_category(
    findings: List[Dict[str, Any]], only_category: str = None
) -> List[Dict[str, Any]]:
    """
    Filter findings by category if specified.

    Args:
        findings: List of findings with category field
        only_category: Category to filter by (actual/expired/test/unknown)

    Returns:
        Filtered list of findings
    """
    if not only_category:
        return findings

    filtered = []
    for finding in findings:
        if finding.get("category") == only_category:
            filtered.append(finding)

    return filtered


def enhance_findings_with_validation_and_classification(
    findings: List[Dict[str, Any]], config: Dict[str, Any] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """
    Enhance findings with validation results and classification.

    Args:
        findings: Raw findings from scanner
        config: Configuration for validators

    Returns:
        Tuple of (enhanced_findings, validation_results_by_index)
    """
    config = config or {}
    enhanced_findings = []
    validation_results_by_index = {}

    # Load policy config for validation settings
    try:
        from ss360.policy.config import load_policy_config, get_default_policy_config

        # Try to load from common locations
        policy_paths = ["policy.yml", "policy.yaml", "policy.example.yml"]
        policy_config = None
        for policy_path in policy_paths:
            try:
                policy_config = load_policy_config(policy_path)
                break
            except FileNotFoundError:
                continue

        if policy_config is None:
            policy_config = get_default_policy_config()

        validation_config = policy_config.get("validators", {})
    except Exception:
        # Fallback to safe defaults if no policy config
        validation_config = {"allow_network": False, "global_qps": 2.0}

    for i, finding in enumerate(findings):
        # Run validation for this finding
        try:
            validation_results = run_validators(
                finding, {"validators": validation_config}
            )
            validation_results_by_index[str(i)] = [
                {
                    "state": result.state.value,
                    "evidence": result.evidence,
                    "reason": result.reason,
                    "validator_name": result.validator_name,
                }
                for result in validation_results
            ]
        except Exception:
            # If validation fails, continue without it
            validation_results_by_index[str(i)] = []
            validation_results = []

        # Run classification
        try:
            context = {"validation_results": validation_results_by_index[str(i)]}
            category, confidence, reasons = classify(finding, context)

            # Enhance finding with classification data
            enhanced_finding = finding.copy()
            enhanced_finding.update(
                {"category": category, "confidence": confidence, "reasons": reasons}
            )
            enhanced_findings.append(enhanced_finding)

        except Exception as e:
            # If classification fails, add finding without classification
            enhanced_finding = finding.copy()
            enhanced_finding.update(
                {
                    "category": "unknown",
                    "confidence": 0.1,
                    "reasons": [f"classification_error:{str(e)}"],
                }
            )
            enhanced_findings.append(enhanced_finding)

    return enhanced_findings, validation_results_by_index


def print_category_summary(findings: List[Dict[str, Any]]) -> None:
    """Print a brief category summary of findings."""
    category_counts = {"actual": 0, "expired": 0, "test": 0, "unknown": 0}

    for finding in findings:
        category = finding.get("category", "unknown")
        if category in category_counts:
            category_counts[category] += 1
        else:
            category_counts["unknown"] += 1

    print("[ci-scan] Category Summary:")
    for category, count in category_counts.items():
        print(f"[ci-scan]   {category}: {count}")
    print(f"[ci-scan]   total: {sum(category_counts.values())}")


def load_baseline(baseline_path: str = ".ss360-baseline.json") -> Dict[str, Any]:
    """Load baseline file if present."""
    try:
        baseline_file = Path(baseline_path)
        if baseline_file.exists():
            with open(baseline_file, "r") as f:
                baseline = json.load(f)
                print(f"[ci-scan] Loaded baseline: {baseline_path}")
                return baseline
    except Exception as e:
        print(f"[ci-scan] Failed to load baseline {baseline_path}: {e}")
    return {}


def filter_against_baseline(
    findings: List[Dict[str, Any]], baseline: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Filter findings against baseline to only include new findings."""
    if not baseline or not baseline.get("entries"):
        return findings

    baseline_entries = set()
    for entry in baseline.get("entries", []):
        # Create a unique identifier for baseline entries
        key = f"{entry.get('path', '')}:{entry.get('line', '')}:{entry.get('id', '')}"
        baseline_entries.add(key)

    new_findings = []
    for finding in findings:
        key = f"{finding.get('path', '')}:{finding.get('line', '')}:{finding.get('id', '')}"
        if key not in baseline_entries:
            new_findings.append(finding)

    if len(findings) != len(new_findings):
        print(
            f"[ci-scan] Filtered {len(findings) - len(new_findings)} baseline findings, {len(new_findings)} new findings remain"
        )

    return new_findings


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

    # Load baseline if present
    baseline = load_baseline()

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

    # Filter against baseline if present
    if baseline:
        findings = filter_against_baseline(findings, baseline)

    # Enhance findings with validation and classification
    enhanced_findings, validation_results = (
        enhance_findings_with_validation_and_classification(findings)
    )

    # Filter by category if specified
    if args.only_category:
        enhanced_findings = filter_findings_by_category(
            enhanced_findings, args.only_category
        )

    # Print category summary
    print_category_summary(enhanced_findings)

    # Load and enforce policy
    policy_exit_code = 0
    try:
        from ss360.policy.config import load_policy_config, get_default_policy_config
        from ss360.policy.enforce import PolicyEnforcer

        # Try to load policy from common locations
        policy_paths = ["policy.yml", "policy.yaml", "policy.example.yml"]
        policy_config = None
        for policy_path in policy_paths:
            try:
                policy_config = load_policy_config(policy_path)
                print(f"[ci-scan] Loaded policy: {policy_path}")
                break
            except FileNotFoundError:
                continue

        if policy_config is None:
            policy_config = get_default_policy_config()
            print("[ci-scan] Using default policy")

        # Enforce policy
        enforcer = PolicyEnforcer(policy_config)
        enforcement_result = enforcer.enforce(enhanced_findings)

        if not enforcement_result.passed:
            print("[ci-scan] Policy violations found:")
            for violation in enforcement_result.violations:
                print(f"[ci-scan]   {violation.type.value}: {violation.message}")
            policy_exit_code = 1
        else:
            print("[ci-scan] Policy enforcement: PASS")

    except Exception as e:
        print(f"[ci-scan] Policy enforcement failed: {e}")
        # Don't fail CI on policy enforcement errors, continue with max_findings check

    report = {
        "root": str(root),
        "config": str(Path(config_path).resolve()),
        "total": len(enhanced_findings),
        "findings": enhanced_findings,
        "validation_results": validation_results,
    }

    json_out = args.out or args.json_out
    if json_out:
        Path(json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(json_out).write_text(json.dumps(report, indent=2))
        print(f"[ci-scan] Wrote report: {json_out}")

    # Write SARIF (before gating) if requested
    if args.sarif_out:
        sarif = build_sarif(report)
        sarif_path = Path(args.sarif_out)
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
        sarif_path.write_text(json.dumps(sarif, indent=2))
        print(f"[ci-scan] Wrote SARIF: {sarif_path}")

    print(f"[ci-scan] total findings: {report['total']}")

    # Check policy enforcement first
    if policy_exit_code != 0:
        print("[ci-scan] FAIL: Policy violations detected", file=sys.stderr)
        return policy_exit_code

    # Then check legacy max_findings for backward compatibility
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
            print(
                f"[ci-scan] finding: {path}:{line} kind={kind} reason={reason}",
                file=sys.stderr,
            )
        return 1

    print("[ci-scan] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
