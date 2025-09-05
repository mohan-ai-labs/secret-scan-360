# SPDX-License-Identifier: MIT
"""
Risk scoring system for security findings.

Provides deterministic risk scoring based on:
- Base severity of the finding type
- Validation state (valid/invalid/indeterminate)
- Repository exposure context
- Path context (production vs test files)
- Historical presence
"""
from __future__ import annotations

from typing import Dict, Any, List
from enum import Enum


class RiskLevel(Enum):
    """Risk level categories."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# Base risk scores by finding type
BASE_RISK_SCORES = {
    "github_pat": 70,
    "aws_keypair": 80,
    "slack_webhook": 40,
    "private_key": 90,
    "api_key": 60,
    "password": 50,
    "database_url": 75,
    "jwt_token": 65,
}

# Path risk multipliers
PATH_RISK_MULTIPLIERS = {
    # Production-like paths - higher risk
    "production": 1.2,
    "prod": 1.2,
    "deploy": 1.2,
    "release": 1.2,
    "config": 1.1,
    "env": 1.1,
    ".env": 1.2,
    # Test-like paths - lower risk
    "test": 0.7,
    "tests": 0.7,
    "spec": 0.7,
    "mock": 0.6,
    "fixture": 0.6,
    "example": 0.5,
    "sample": 0.5,
    "demo": 0.5,
    "readme": 0.3,
    "doc": 0.3,
    "docs": 0.3,
}


def calculate_risk_score(
    finding: Dict[str, Any],
    validation_results: List[Dict[str, Any]] = None,
    repo_context: Dict[str, Any] = None,
) -> int:
    """
    Calculate risk score for a finding.

    Args:
        finding: The security finding
        validation_results: List of validation results
        repo_context: Repository context information

    Returns:
        Risk score between 0-100
    """
    validation_results = validation_results or []
    repo_context = repo_context or {}

    # Base score from finding type
    finding_id = finding.get("id", "unknown")
    base_score = BASE_RISK_SCORES.get(finding_id, 50)

    # Start with base score
    score = float(base_score)

    # Validation state modifier
    validation_modifier = _get_validation_modifier(validation_results)
    score *= validation_modifier

    # Path context modifier
    path = finding.get("path", "")
    path_modifier = _get_path_modifier(path)
    score *= path_modifier

    # Repository exposure modifier
    exposure_modifier = _get_exposure_modifier(repo_context)
    score *= exposure_modifier

    # Historical presence modifier
    history_modifier = _get_history_modifier(finding)
    score *= history_modifier

    # Category modifier - boost actual, downrank expired/test
    category_modifier = _get_category_modifier(finding)
    score *= category_modifier

    # Clamp to 0-100 range
    return max(0, min(100, int(round(score))))


def _get_validation_modifier(validation_results: List[Dict[str, Any]]) -> float:
    """Get risk modifier based on validation state."""
    if not validation_results:
        return 1.0  # No validation info

    # Check if any validator confirmed the finding as valid
    has_valid = any(r.get("state") == "valid" for r in validation_results)
    has_invalid = any(r.get("state") == "invalid" for r in validation_results)

    if has_valid:
        return 1.3  # Confirmed valid - higher risk
    elif has_invalid:
        return 0.4  # Confirmed invalid - much lower risk
    else:
        return 0.9  # Indeterminate - slightly lower risk


def _get_path_modifier(path: str) -> float:
    """Get risk modifier based on file path context."""
    if not path:
        return 1.0

    path_lower = path.lower()

    # Check for path indicators
    for indicator, multiplier in PATH_RISK_MULTIPLIERS.items():
        if indicator in path_lower:
            return multiplier

    # Default modifier
    return 1.0


def _get_exposure_modifier(repo_context: Dict[str, Any]) -> float:
    """Get risk modifier based on repository exposure."""
    if not repo_context:
        return 1.0

    is_public = repo_context.get("is_public", False)
    has_external_contributors = repo_context.get("has_external_contributors", False)

    if is_public:
        return 1.2  # Public repos are higher risk
    elif has_external_contributors:
        return 1.1  # External contributors increase risk slightly
    else:
        return 1.0  # Private internal repos


def _get_history_modifier(finding: Dict[str, Any]) -> float:
    """Get risk modifier based on historical presence."""
    # If finding has been in history for a long time, it's potentially higher risk
    # as it may have been exposed/used more
    history_age_days = finding.get("history_age_days", 0)

    if history_age_days > 365:
        return 1.2  # Over a year old - higher risk
    elif history_age_days > 90:
        return 1.1  # Over 3 months old - slightly higher risk
    else:
        return 1.0  # Recent or no history info


def _get_category_modifier(finding: Dict[str, Any]) -> float:
    """Get risk modifier based on finding category."""
    category = finding.get("category", "unknown")

    if category == "actual":
        return 1.3  # Boost actual findings significantly
    elif category == "expired":
        return 0.3  # Expired credentials are lower risk
    elif category == "test":
        return 0.2  # Test credentials are very low risk
    elif category == "unknown":
        return 1.0  # No modification for unknown
    else:
        return 1.0  # Default for any new categories


def get_risk_level(score: int) -> RiskLevel:
    """Convert numeric risk score to risk level."""
    if score >= 80:
        return RiskLevel.CRITICAL
    elif score >= 60:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    elif score >= 20:
        return RiskLevel.LOW
    else:
        return RiskLevel.INFO


def risk_summary(
    finding: Dict[str, Any],
    validation_results: List[Dict[str, Any]] = None,
    repo_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Generate a complete risk summary for a finding.

    Returns:
        Dictionary with score, level, and contributing factors
    """
    score = calculate_risk_score(finding, validation_results, repo_context)
    level = get_risk_level(score)

    return {
        "score": score,
        "level": level.value,
        "factors": {
            "base_score": BASE_RISK_SCORES.get(finding.get("id", "unknown"), 50),
            "validation_modifier": _get_validation_modifier(validation_results or []),
            "path_modifier": _get_path_modifier(finding.get("path", "")),
            "exposure_modifier": _get_exposure_modifier(repo_context or {}),
            "history_modifier": _get_history_modifier(finding),
            "category_modifier": _get_category_modifier(finding),
        },
    }
