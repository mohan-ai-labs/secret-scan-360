# SPDX-License-Identifier: MIT
"""
Secret Scan 360 - Command Line Interface

This CLI provides:
- ss360 version
- ss360 scan <root> --format {text,json,sarif} --policy <path> --autofix {plan|apply}

Note:
- All example strings have been sanitized to avoid triggering detectors.
"""

import argparse
import sys
import json
from pathlib import Path
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
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="output format (default: text)"
    )
    sp.add_argument(
        "--policy",
        help="path to policy YAML file"
    )
    sp.add_argument(
        "--autofix",
        choices=["plan", "apply"],
        help="generate autofix plan or apply fixes"
    )
    sp.add_argument(
        "--i-know-what-im-doing",
        action="store_true",
        help="required for apply mode with destructive operations"
    )
    sp.add_argument(
        "--json-out",
        dest="json_out",
        help="write JSON results to file"
    )
    sp.add_argument(
        "--sarif-out",
        dest="sarif_out",
        help="write SARIF results to file"
    )

    args = p.parse_args(argv)

    if args.version or args.cmd == "version":
        print(__version__)
        return 0

    if args.cmd == "scan":
        return handle_scan_command(args)

    p.print_help()
    return 0


def handle_scan_command(args):
    """Handle the scan subcommand."""
    from services.agents.app.core.scanner import Scanner
    from services.agents.app.detectors.registry import DetectorRegistry
    from .policy.loader import load_policy_config, get_default_policy_config
    from .policy.enforce import enforce_policy
    from .validate.core import run_validators, ValidatorRegistry
    from .validate.live_validators import GitHubPATLiveValidator, AWSAccessKeyLiveValidator
    from .risk.score import calculate_risk_score, risk_summary
    from .autofix.planner import AutofixPlanner, format_plan_for_display
    from .autofix.apply import AutofixApplier

    # Load policy configuration
    if args.policy:
        try:
            policy_config = load_policy_config(args.policy)
        except Exception as e:
            print(f"Error loading policy: {e}", file=sys.stderr)
            return 1
    else:
        policy_config = get_default_policy_config()
        if args.format == "text":
            print("Using default policy (no --policy specified)")

    # Initialize detector registry with our detectors
    detector_registry = DetectorRegistry()

    # Import and register our detectors
    import detectors.github_pat as github_pat_detector
    import detectors.aws_keypair as aws_keypair_detector

    # Create simple detector wrapper
    class SimpleDetector:
        def __init__(self, name, detector_id, detect_func):
            self.name = name
            self.detector_id = detector_id
            self.detect_func = detect_func

        def detect(self, path: str, text: str):
            lines = text.splitlines()
            for finding in self.detect_func(lines):
                finding["path"] = path
                finding["kind"] = self.detector_id  # Use detector_id as kind
                yield finding

    # Register our detectors
    github_detector = SimpleDetector("github_pat", "github_pat", github_pat_detector.detect)
    aws_detector = SimpleDetector("aws_keypair", "aws_keypair", aws_keypair_detector.detect)

    detector_registry.register(github_detector)
    detector_registry.register(aws_detector)

    # Initialize scanner
    scanner = Scanner(registry=detector_registry)

    # Perform scan
    try:
        findings = scanner.scan_paths([args.root])
    except Exception as e:
        print(f"Error during scan: {e}", file=sys.stderr)
        return 1

    # Convert findings to our expected format
    normalized_findings = []
    for finding in findings:
        normalized_finding = {
            "id": finding.get("kind", "unknown"),
            "title": finding.get("kind", "Unknown"),
            "path": finding.get("path", ""),
            "line": finding.get("line", 0),
            "match": finding.get("match", ""),
            "severity": "high",  # Default severity
            "description": f"{finding.get('kind', 'Unknown')} detected",
        }
        normalized_findings.append(normalized_finding)

    # Build scan results
    scan_results = {
        "total": len(normalized_findings),
        "findings": normalized_findings
    }

    # Set up validator registry
    validator_registry = ValidatorRegistry()
    validator_registry.register(GitHubPATLiveValidator())
    validator_registry.register(AWSAccessKeyLiveValidator())

    # Run validation for each finding
    validation_results = {}
    for i, finding in enumerate(normalized_findings):
        results = run_validators(finding, policy_config, validator_registry)
        validation_results[str(i)] = [
            {
                "state": r.state.value,
                "evidence": r.evidence,
                "reason": r.reason,
                "validator_name": r.validator_name
            }
            for r in results
        ]

        # Calculate risk score
        risk_score = calculate_risk_score(finding, [r.__dict__ for r in results])
        finding["risk_score"] = risk_score
        finding["risk_summary"] = risk_summary(finding, [r.__dict__ for r in results])

    # Add validation results to scan results
    scan_results["validators"] = {
        "enabled": True,
        "results": validation_results
    }

    # Enforce policy
    policy_result = enforce_policy(policy_config, normalized_findings, validation_results)
    scan_results["policy"] = {
        "passed": policy_result.passed,
        "violations": [
            {
                "type": v.type.value,
                "message": v.message,
                "severity": v.severity,
                "finding_id": v.finding_id,
                "path": v.path
            }
            for v in policy_result.violations
        ],
        "summary": policy_result.summary
    }

    # Handle autofix
    if args.autofix:
        planner = AutofixPlanner()
        # Extract autofix config
        autofix_config = policy_config.get("autofix", {})
        plan_items = planner.generate_plan(normalized_findings, autofix_config)

        if args.autofix == "plan":
            plan_display = format_plan_for_display(plan_items)
            if args.format == "text":
                print("\n" + plan_display)
            scan_results["autofix_plan"] = [
                {
                    "action": item.action.value,
                    "path": item.path,
                    "line": item.line,
                    "replacement": item.replacement,
                    "provider": item.provider,
                    "reversible": item.reversible,
                    "description": item.description,
                    "safety_check": item.safety_check
                }
                for item in plan_items
            ]

        elif args.autofix == "apply":
            if not args.i_know_what_im_doing:
                print("ERROR: --autofix apply requires --i-know-what-im-doing flag", file=sys.stderr)
                return 1

            applier = AutofixApplier(dry_run=False)
            apply_result = applier.apply_plan(plan_items, confirmation_required=True)
            scan_results["autofix_result"] = apply_result

            if args.format == "text":
                print(f"\nAutofix completed: {apply_result['status']}")
                if apply_result.get("pull_request"):
                    pr_info = apply_result["pull_request"]
                    print(f"Pull request: {pr_info.get('pr_url', pr_info.get('branch'))}")

    # Output results
    if args.format == "json" or args.json_out:
        json_output = json.dumps(scan_results, indent=2, default=str)
        if args.json_out:
            Path(args.json_out).write_text(json_output)
            if args.format == "text":
                print(f"JSON output written to {args.json_out}")
        if args.format == "json":
            print(json_output)

    elif args.format == "sarif" or args.sarif_out:
        sarif_output = convert_to_sarif(scan_results)
        sarif_json = json.dumps(sarif_output, indent=2)
        if args.sarif_out:
            Path(args.sarif_out).write_text(sarif_json)
            if args.format == "text":
                print(f"SARIF output written to {args.sarif_out}")
        if args.format == "sarif":
            print(sarif_json)

    elif args.format == "text":
        print_text_summary(scan_results, policy_result)

    # Exit with appropriate code
    if not policy_result.passed:
        return 1

    return 0


def convert_to_sarif(scan_results):
    """Convert scan results to SARIF format."""
    findings = scan_results.get("findings", [])

    sarif = {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SS360",
                        "version": __version__,
                        "informationUri": "https://github.com/mohan-ai-labs/secret-scan-360",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }

    # Extract unique rules from findings
    rules_seen = set()
    run = sarif["runs"][0]

    for finding in findings:
        rule_id = finding.get("id", "unknown")
        if rule_id not in rules_seen:
            rule = {
                "id": rule_id,
                "name": finding.get("title", rule_id),
                "shortDescription": {
                    "text": finding.get("description", "Security finding")
                },
                "defaultConfiguration": {
                    "level": "error" if finding.get("severity") == "high" else "warning"
                }
            }
            run["tool"]["driver"]["rules"].append(rule)
            rules_seen.add(rule_id)

        # Create result
        result = {
            "ruleId": rule_id,
            "message": {
                "text": finding.get("description", "Security finding detected")
            },
            "level": "error" if finding.get("severity") == "high" else "warning",
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("path", "unknown")
                        },
                        "region": {
                            "startLine": finding.get("line", 1)
                        }
                    }
                }
            ]
        }

        # Add risk information as properties
        if "risk_score" in finding:
            result["properties"] = {
                "risk_score": finding["risk_score"],
                "risk_level": finding.get("risk_summary", {}).get("level", "unknown")
            }

        run["results"].append(result)

    return sarif


def print_text_summary(scan_results, policy_result):
    """Print a text summary of scan results."""
    findings = scan_results.get("findings", [])
    validators_info = scan_results.get("validators", {})
    policy_info = scan_results.get("policy", {})

    print("\n🔍 SS360 Scan Results")
    print("=" * 50)

    print(f"Total findings: {len(findings)}")

    if findings:
        print("\nFindings by type:")
        finding_counts = {}
        for finding in findings:
            finding_type = finding.get("id", "unknown")
            finding_counts[finding_type] = finding_counts.get(finding_type, 0) + 1

        for finding_type, count in finding_counts.items():
            print(f"  {finding_type}: {count}")

        print("\nHigh-risk findings:")
        high_risk_count = sum(1 for f in findings if f.get("risk_score", 0) >= 60)
        print(f"  Count: {high_risk_count}")

    # Validator summary
    if validators_info.get("enabled"):
        print("\n🔬 Validation Summary")
        validation_results = validators_info.get("results", {})

        total_validations = sum(len(results) for results in validation_results.values())
        if total_validations > 0:
            valid_count = sum(
                1 for results in validation_results.values()
                for result in results
                if result.get("state") == "valid"
            )
            print(f"  Total validations: {total_validations}")
            print(f"  Confirmed valid: {valid_count}")

    # Policy summary
    print("\n📋 Policy Enforcement")
    if policy_info.get("passed"):
        print("  Status: ✅ PASSED")
    else:
        print("  Status: ❌ FAILED")
        violations = policy_info.get("violations", [])
        print(f"  Violations: {len(violations)}")
        for violation in violations[:3]:  # Show first 3 violations
            print(f"    - {violation['message']}")
        if len(violations) > 3:
            print(f"    ... and {len(violations) - 3} more")


if __name__ == "__main__":
    raise SystemExit(main())