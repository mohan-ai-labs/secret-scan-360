# SPDX-License-Identifier: MIT
"""
Policy enforcement engine.
"""
from __future__ import annotations

from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum

from .loader import is_waiver_active, get_active_waivers


class PolicyViolationType(Enum):
    """Types of policy violations."""

    BUDGET_EXCEEDED = "budget_exceeded"
    RISK_SCORE_TOO_HIGH = "risk_score_too_high"
    NETWORK_DISABLED = "network_disabled"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"


@dataclass
class PolicyViolation:
    """A policy violation."""

    type: PolicyViolationType
    message: str
    severity: str
    finding_id: str = ""
    path: str = ""
    details: Dict[str, Any] = None


@dataclass
class PolicyEnforcementResult:
    """Result of policy enforcement."""

    passed: bool
    violations: List[PolicyViolation]
    waivers_applied: List[Dict[str, Any]]
    summary: Dict[str, Any]


class PolicyEnforcer:
    """Enforces policy rules against scan results."""

    def __init__(self, policy_config: Dict[str, Any]):
        self.config = policy_config

    def enforce(
        self,
        findings: List[Dict[str, Any]],
        validation_results: Dict[str, List[Dict[str, Any]]] = None,
    ) -> PolicyEnforcementResult:
        """
        Enforce policy against scan findings.

        Args:
            findings: List of security findings
            validation_results: Dictionary mapping finding IDs to validation results

        Returns:
            PolicyEnforcementResult with violations and summary
        """
        validation_results = validation_results or {}
        violations = []
        waivers_applied = []

        # Filter findings through active waivers
        filtered_findings = []
        for finding in findings:
            finding_path = finding.get("path", "")
            rule_id = finding.get("id", "")

            # Check if any waiver applies
            waiver_found = False
            for waiver in get_active_waivers(self.config):
                if is_waiver_active(waiver, finding_path, rule_id):
                    waivers_applied.append(
                        {"finding": f"{rule_id}:{finding_path}", "waiver": waiver}
                    )
                    waiver_found = True
                    break

            if not waiver_found:
                filtered_findings.append(finding)

        # Check budget violations
        budget_violations = self._check_budget_violations(filtered_findings)
        violations.extend(budget_violations)

        # Check risk score violations
        risk_violations = self._check_risk_score_violations(
            filtered_findings, validation_results
        )
        violations.extend(risk_violations)

        # Check validator configuration violations
        validator_violations = self._check_validator_violations(validation_results)
        violations.extend(validator_violations)

        # Calculate summary
        summary = {
            "total_findings": len(findings),
            "filtered_findings": len(filtered_findings),
            "violations": len(violations),
            "waivers_applied": len(waivers_applied),
            "passed": len(violations) == 0,
        }

        return PolicyEnforcementResult(
            passed=len(violations) == 0,
            violations=violations,
            waivers_applied=waivers_applied,
            summary=summary,
        )

    def _check_budget_violations(
        self, findings: List[Dict[str, Any]]
    ) -> List[PolicyViolation]:
        """Check budget constraint violations."""
        violations = []
        budgets = self.config.get("budgets", {})

        # Check legacy new findings budget (backward compatibility)
        max_new_findings = budgets.get("new_findings", None)
        if max_new_findings is not None and len(findings) > max_new_findings:
            violations.append(
                PolicyViolation(
                    type=PolicyViolationType.BUDGET_EXCEEDED,
                    message=f"Found {len(findings)} findings, but budget allows max {max_new_findings}",
                    severity="high",
                    details={
                        "found": len(findings),
                        "allowed": max_new_findings,
                        "budget_type": "new_findings",
                    },
                )
            )

        # Check category-based budgets
        category_budgets = {
            "new_actual_findings": budgets.get("new_actual_findings"),
            "new_expired_findings": budgets.get("new_expired_findings"),
            "new_test_findings": budgets.get("new_test_findings"),
            "new_unknown_findings": budgets.get("new_unknown_findings"),
        }

        # Count findings by category
        category_counts = {"actual": 0, "expired": 0, "test": 0, "unknown": 0}
        for finding in findings:
            category = finding.get("category", "unknown")
            if category in category_counts:
                category_counts[category] += 1

        # Check each category budget
        for budget_key, budget_limit in category_budgets.items():
            if budget_limit is None:
                continue  # Skip undefined budgets

            category = budget_key.replace("new_", "").replace("_findings", "")
            found_count = category_counts.get(category, 0)

            if found_count > budget_limit:
                violations.append(
                    PolicyViolation(
                        type=PolicyViolationType.BUDGET_EXCEEDED,
                        message=f"Found {found_count} {category} findings, but budget allows max {budget_limit}",
                        severity="high",
                        details={
                            "found": found_count,
                            "allowed": budget_limit,
                            "budget_type": budget_key,
                            "category": category,
                        },
                    )
                )

        return violations

    def _check_risk_score_violations(
        self,
        findings: List[Dict[str, Any]],
        validation_results: Dict[str, List[Dict[str, Any]]],
    ) -> List[PolicyViolation]:
        """Check risk score violations."""
        violations = []
        budgets = self.config.get("budgets", {})
        max_risk_score = budgets.get(
            "max_risk_score", 999
        )  # High default to focus on category budgets

        for i, finding in enumerate(findings):
            # Calculate risk score if not already present
            risk_score = finding.get("risk_score")
            if risk_score is None:
                # Import and calculate risk score
                from ..risk.score import calculate_risk_score

                validation_data = validation_results.get(str(i), [])
                risk_score = calculate_risk_score(finding, validation_data)
                finding["risk_score"] = risk_score

            if risk_score > max_risk_score:
                violations.append(
                    PolicyViolation(
                        type=PolicyViolationType.RISK_SCORE_TOO_HIGH,
                        message=f"Finding has risk score {risk_score}, exceeds limit {max_risk_score}",
                        severity="high",
                        finding_id=finding.get("id", ""),
                        path=finding.get("path", ""),
                        details={
                            "risk_score": risk_score,
                            "max_allowed": max_risk_score,
                            "finding": finding,
                        },
                    )
                )

        return violations

    def _check_validator_violations(
        self, validation_results: Dict[str, List[Dict[str, Any]]]
    ) -> List[PolicyViolation]:
        """Check validator configuration violations."""
        violations = []
        validators_config = self.config.get("validators", {})

        # Check if network validators were disabled when they should be allowed
        allow_network = validators_config.get("allow_network", False)

        # Count network-disabled validator results
        network_disabled_count = 0
        for results in validation_results.values():
            for result in results:
                if result.get("reason") == "Network disabled - validator skipped":
                    network_disabled_count += 1

        # This is more informational than a violation
        if network_disabled_count > 0 and not allow_network:
            # Not a violation, just note that network validation was skipped
            pass

        return violations

    def format_violations_report(self, result: PolicyEnforcementResult) -> str:
        """Format policy violations as a human-readable report."""
        if result.passed:
            return "✅ All policy checks passed."

        report = ["❌ Policy violations found:", ""]

        for violation in result.violations:
            severity_icon = "🔴" if violation.severity == "high" else "🟡"
            report.append(
                f"{severity_icon} {violation.type.value}: {violation.message}"
            )

            if violation.path:
                report.append(f"   File: {violation.path}")
            if violation.finding_id:
                report.append(f"   Rule: {violation.finding_id}")

            report.append("")

        # Add summary
        summary = result.summary
        report.extend(
            [
                "Summary:",
                f"  Total findings: {summary['total_findings']}",
                f"  After waivers: {summary['filtered_findings']}",
                f"  Violations: {summary['violations']}",
                f"  Waivers applied: {summary['waivers_applied']}",
            ]
        )

        return "\n".join(report)


def enforce_policy(
    policy_config: Dict[str, Any],
    findings: List[Dict[str, Any]],
    validation_results: Dict[str, List[Dict[str, Any]]] = None,
) -> PolicyEnforcementResult:
    """
    Convenience function to enforce policy.

    Args:
        policy_config: Policy configuration
        findings: List of security findings
        validation_results: Validation results by finding index

    Returns:
        PolicyEnforcementResult
    """
    enforcer = PolicyEnforcer(policy_config)
    return enforcer.enforce(findings, validation_results)
