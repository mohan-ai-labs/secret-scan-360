#!/usr/bin/env python3
"""
SARIF Aggregator - Aggregate SARIF across repos and map to owners via CODEOWNERS.

This tool aggregates SARIF findings from multiple repositories, maps findings to code owners
based on CODEOWNERS files, and produces summary reports in JSON and Markdown formats.
"""

from __future__ import annotations

import argparse
import json
import fnmatch
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict


class CodeOwnersParser:
    """Parser for CODEOWNERS files with glob pattern matching."""

    def __init__(self, codeowners_content: str):
        self.rules = []
        self._parse(codeowners_content)

    def _parse(self, content: str) -> None:
        """Parse CODEOWNERS content and extract rules."""
        for line in content.splitlines():
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            pattern = parts[0]
            owners = parts[1:]  # All remaining parts are owners
            self.rules.append((pattern, owners))

    def get_owners(self, file_path: str) -> List[str]:
        """Get owners for a file path. Last matching rule wins."""
        owners = []
        for pattern, rule_owners in self.rules:
            if self._matches_pattern(pattern, file_path):
                owners = rule_owners
        return owners

    def _matches_pattern(self, pattern: str, file_path: str) -> bool:
        """Check if a file path matches a CODEOWNERS pattern."""
        # Normalize paths
        file_path = file_path.lstrip("/")
        pattern = pattern.lstrip("/")

        # Handle directory patterns
        if pattern.endswith("/"):
            # Directory pattern matches files within that directory
            return file_path.startswith(pattern) or fnmatch.fnmatch(
                file_path, pattern + "*"
            )

        # Use fnmatch for glob patterns
        return fnmatch.fnmatch(file_path, pattern)


class SarifAggregator:
    """Aggregates SARIF findings across repositories and maps to code owners."""

    def __init__(self, artifacts_dir: Path):
        self.artifacts_dir = Path(artifacts_dir)
        self.findings = []
        self.summary_data = {
            "total_findings": 0,
            "by_owner": defaultdict(lambda: defaultdict(int)),
            "by_repo": defaultdict(lambda: defaultdict(int)),
            "by_rule": defaultdict(int),
            "by_severity": defaultdict(int),
            "by_category": defaultdict(int),
            "repos_scanned": [],
        }

    def aggregate(self) -> Dict[str, Any]:
        """Aggregate all SARIF files and return summary data."""
        sarif_files = self._find_sarif_files()

        for sarif_file in sarif_files:
            repo_name = self._get_repo_name(sarif_file)
            self.summary_data["repos_scanned"].append(repo_name)

            # Load CODEOWNERS for this repo
            codeowners_parser = self._load_codeowners(sarif_file)

            # Process SARIF file
            self._process_sarif_file(sarif_file, repo_name, codeowners_parser)

        # Convert defaultdicts to regular dicts for JSON serialization
        self.summary_data["by_owner"] = {
            k: dict(v) for k, v in self.summary_data["by_owner"].items()
        }
        self.summary_data["by_repo"] = {
            k: dict(v) for k, v in self.summary_data["by_repo"].items()
        }
        self.summary_data["by_rule"] = dict(self.summary_data["by_rule"])
        self.summary_data["by_severity"] = dict(self.summary_data["by_severity"])
        self.summary_data["by_category"] = dict(self.summary_data["by_category"])

        return self.summary_data

    def _find_sarif_files(self) -> List[Path]:
        """Find all findings.sarif files in the artifacts directory."""
        pattern = "**/findings.sarif"
        return list(self.artifacts_dir.glob(pattern))

    def _get_repo_name(self, sarif_file: Path) -> str:
        """Extract repository name from SARIF file path."""
        # Assume structure: .artifacts/org/{repo_name}/findings.sarif
        relative_path = sarif_file.relative_to(self.artifacts_dir)
        parts = relative_path.parts
        if len(parts) >= 2:
            return parts[-2]  # repo name is the parent directory of findings.sarif
        return "unknown"

    def _load_codeowners(self, sarif_file: Path) -> Optional[CodeOwnersParser]:
        """Load CODEOWNERS file for the repository."""
        repo_dir = sarif_file.parent
        codeowners_file = repo_dir / "CODEOWNERS"

        if codeowners_file.exists():
            content = codeowners_file.read_text(encoding="utf-8")
            return CodeOwnersParser(content)
        return None

    def _process_sarif_file(
        self,
        sarif_file: Path,
        repo_name: str,
        codeowners_parser: Optional[CodeOwnersParser],
    ) -> None:
        """Process a single SARIF file and update summary data."""
        try:
            with open(sarif_file, "r", encoding="utf-8") as f:
                sarif_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not process {sarif_file}: {e}")
            return

        runs = sarif_data.get("runs", [])
        for run in runs:
            results = run.get("results", [])
            rules = {
                rule["id"]: rule
                for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            }

            for result in results:
                self._process_result(result, repo_name, rules, codeowners_parser)

    def _process_result(
        self,
        result: Dict[str, Any],
        repo_name: str,
        rules: Dict[str, Any],
        codeowners_parser: Optional[CodeOwnersParser],
    ) -> None:
        """Process a single SARIF result and update summary data."""
        rule_id = result.get("ruleId", "Unknown")
        level = result.get("level", "error")
        properties = result.get("properties", {})
        category = properties.get("category", "unknown")

        # Get file path from the first location
        locations = result.get("locations", [])
        file_path = "unknown"
        if locations:
            physical_location = locations[0].get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            file_path = artifact_location.get("uri", "unknown")

        # Determine owners
        owners = []
        if codeowners_parser:
            owners = codeowners_parser.get_owners(file_path)
        if not owners:
            owners = ["@unowned"]

        # Update summary data
        self.summary_data["total_findings"] += 1
        self.summary_data["by_rule"][rule_id] += 1
        self.summary_data["by_severity"][level] += 1
        self.summary_data["by_category"][category] += 1

        # Update by repo
        self.summary_data["by_repo"][repo_name]["total"] += 1
        self.summary_data["by_repo"][repo_name][category] += 1

        # Update by owner
        for owner in owners:
            self.summary_data["by_owner"][owner]["total"] += 1
            self.summary_data["by_owner"][owner][category] += 1
            self.summary_data["by_owner"][owner][rule_id] = (
                self.summary_data["by_owner"][owner].get(rule_id, 0) + 1
            )

        # Store detailed finding
        finding = {
            "repo": repo_name,
            "rule": rule_id,
            "severity": level,
            "category": category,
            "file": file_path,
            "owners": owners,
            "message": result.get("message", {}).get("text", ""),
            "line": (
                locations[0]
                .get("physicalLocation", {})
                .get("region", {})
                .get("startLine")
                if locations
                else None
            ),
        }
        self.findings.append(finding)

    def generate_json_summary(self, output_path: Path) -> None:
        """Generate JSON summary file."""
        output_path.write_text(
            json.dumps(self.summary_data, indent=2), encoding="utf-8"
        )

    def generate_markdown_summary(self, output_path: Path) -> None:
        """Generate Markdown summary file."""
        lines = []
        lines.append("# Organization Security Summary")
        lines.append("")
        lines.append(f"**Total Findings:** {self.summary_data['total_findings']}")
        lines.append(
            f"**Repositories Scanned:** {len(self.summary_data['repos_scanned'])}"
        )
        lines.append("")

        # Top owners by finding count
        lines.append("## Top Code Owners by Finding Count")
        lines.append("")
        owner_totals = [
            (owner, data["total"])
            for owner, data in self.summary_data["by_owner"].items()
        ]
        owner_totals.sort(key=lambda x: x[1], reverse=True)

        lines.append("| Owner | Total Findings | Actual | Test | Expired | Unknown |")
        lines.append("|-------|----------------|--------|------|---------|---------|")

        for owner, total in owner_totals[:10]:  # Top 10 owners
            owner_data = self.summary_data["by_owner"][owner]
            actual = owner_data.get("actual", 0)
            test = owner_data.get("test", 0)
            expired = owner_data.get("expired", 0)
            unknown = owner_data.get("unknown", 0)
            lines.append(
                f"| {owner} | {total} | {actual} | {test} | {expired} | {unknown} |"
            )
        lines.append("")

        # Top repositories by finding count
        lines.append("## Top Repositories by Finding Count")
        lines.append("")
        repo_totals = [
            (repo, data["total"]) for repo, data in self.summary_data["by_repo"].items()
        ]
        repo_totals.sort(key=lambda x: x[1], reverse=True)

        lines.append(
            "| Repository | Total Findings | Actual | Test | Expired | Unknown |"
        )
        lines.append(
            "|------------|----------------|--------|------|---------|---------|"
        )

        for repo, total in repo_totals:
            repo_data = self.summary_data["by_repo"][repo]
            actual = repo_data.get("actual", 0)
            test = repo_data.get("test", 0)
            expired = repo_data.get("expired", 0)
            unknown = repo_data.get("unknown", 0)
            lines.append(
                f"| {repo} | {total} | {actual} | {test} | {expired} | {unknown} |"
            )
        lines.append("")

        # Summary by rule type
        lines.append("## Findings by Rule Type")
        lines.append("")
        rule_items = list(self.summary_data["by_rule"].items())
        rule_items.sort(key=lambda x: x[1], reverse=True)

        lines.append("| Rule | Count |")
        lines.append("|------|-------|")
        for rule, count in rule_items:
            lines.append(f"| {rule} | {count} |")
        lines.append("")

        # Summary by category
        lines.append("## Findings by Category")
        lines.append("")
        category_items = list(self.summary_data["by_category"].items())
        category_items.sort(key=lambda x: x[1], reverse=True)

        lines.append("| Category | Count | Description |")
        lines.append("|----------|-------|-------------|")
        category_descriptions = {
            "actual": "Live secrets that pose immediate risk",
            "expired": "Expired or revoked secrets",
            "test": "Test/demo/placeholder secrets",
            "unknown": "Secrets with uncertain status",
        }
        for category, count in category_items:
            description = category_descriptions.get(category, "Unknown category")
            lines.append(f"| {category} | {count} | {description} |")
        lines.append("")

        # Repository links
        lines.append("## Repository SARIF Files")
        lines.append("")
        for repo in self.summary_data["repos_scanned"]:
            sarif_path = f".artifacts/org/{repo}/findings.sarif"
            lines.append(f"- [{repo}]({sarif_path})")

        output_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    """Main entry point for the SARIF aggregator."""
    parser = argparse.ArgumentParser(
        description="Aggregate SARIF findings across repositories"
    )
    parser.add_argument(
        "--in",
        dest="input_dir",
        default=".artifacts/org",
        help="Input directory containing repo SARIF files (default: .artifacts/org)",
    )
    parser.add_argument(
        "--out",
        dest="output_dir",
        default=".artifacts",
        help="Output directory for summary files (default: .artifacts)",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    if not input_dir.exists():
        print(f"Error: Input directory {input_dir} does not exist")
        return 1

    # Ensure output directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    # Run aggregation
    aggregator = SarifAggregator(input_dir)
    summary_data = aggregator.aggregate()

    # Generate outputs
    json_output = output_dir / "org-summary.json"
    md_output = output_dir / "org-summary.md"

    aggregator.generate_json_summary(json_output)
    aggregator.generate_markdown_summary(md_output)

    print(
        f"Aggregated {summary_data['total_findings']} findings from {len(summary_data['repos_scanned'])} repositories"
    )
    print(f"JSON summary: {json_output}")
    print(f"Markdown summary: {md_output}")

    return 0


if __name__ == "__main__":
    exit(main())
