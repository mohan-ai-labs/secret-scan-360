# SPDX-License-Identifier: MIT
"""
Tests for risk scoring system.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ss360.risk.score import (
    calculate_risk_score,
    get_risk_level,
    risk_summary,
    RiskLevel,
    BASE_RISK_SCORES,
)


class TestRiskScoring:
    """Test risk scoring functionality."""

    def test_base_risk_scores(self):
        """Test base risk scores for different finding types."""
        # GitHub PAT
        finding = {"id": "github_pat", "path": "config.py", "line": 10}
        score = calculate_risk_score(finding)
        assert score == BASE_RISK_SCORES["github_pat"]  # 70

        # AWS key
        finding = {"id": "aws_keypair", "path": "deploy.sh", "line": 5}
        score = calculate_risk_score(finding)
        assert score == BASE_RISK_SCORES["aws_keypair"]  # 80

        # Unknown type gets default
        finding = {"id": "unknown_type", "path": "file.py", "line": 1}
        score = calculate_risk_score(finding)
        assert score == 50  # Default base score

    def test_validation_state_modifiers(self):
        """Test risk score modifications based on validation state."""
        finding = {"id": "github_pat", "path": "config.py", "line": 10}

        # Valid finding - increased risk
        valid_results = [{"state": "valid", "evidence": "token works"}]
        score = calculate_risk_score(finding, valid_results)
        assert score > BASE_RISK_SCORES["github_pat"]

        # Invalid finding - decreased risk
        invalid_results = [{"state": "invalid", "evidence": "token invalid"}]
        score = calculate_risk_score(finding, invalid_results)
        assert score < BASE_RISK_SCORES["github_pat"]

        # Indeterminate - slightly decreased risk
        indet_results = [{"state": "indeterminate", "evidence": "unknown"}]
        score = calculate_risk_score(finding, indet_results)
        assert score < BASE_RISK_SCORES["github_pat"]

    def test_path_context_modifiers(self):
        """Test risk score modifications based on file path context."""
        base_finding = {"id": "github_pat", "line": 10}

        # Production paths - higher risk
        prod_finding = {**base_finding, "path": "production/config.py"}
        prod_score = calculate_risk_score(prod_finding)

        normal_finding = {**base_finding, "path": "src/utils.py"}
        normal_score = calculate_risk_score(normal_finding)

        test_finding = {**base_finding, "path": "tests/test_auth.py"}
        test_score = calculate_risk_score(test_finding)

        assert prod_score > normal_score > test_score

    def test_risk_levels(self):
        """Test risk level categorization."""
        assert get_risk_level(90) == RiskLevel.CRITICAL
        assert get_risk_level(70) == RiskLevel.HIGH
        assert get_risk_level(50) == RiskLevel.MEDIUM
        assert get_risk_level(30) == RiskLevel.LOW
        assert get_risk_level(10) == RiskLevel.INFO

    def test_risk_summary(self):
        """Test complete risk summary generation."""
        finding = {
            "id": "github_pat",
            "path": "config/production.py",
            "line": 15
        }

        validation_results = [{"state": "valid", "evidence": "confirmed"}]

        summary = risk_summary(finding, validation_results)

        assert "score" in summary
        assert "level" in summary
        assert "factors" in summary
        assert summary["score"] > 0
        assert summary["level"] in ["critical", "high", "medium", "low", "info"]

        factors = summary["factors"]
        assert "base_score" in factors
        assert "validation_modifier" in factors
        assert "path_modifier" in factors


def test_github_pat_detector():
    """Test GitHub PAT detector patterns."""
    try:
        from src.services.agents.app.detectors.github_pat import detect
    except ImportError:
        from services.agents.app.detectors.github_pat import detect

    # Test classic PAT
    lines = ["API_TOKEN = ghp_1234567890123456789012345678901234567890"]
    findings = list(detect(lines))
    assert len(findings) == 1
    assert findings[0]["id"] == "github_pat"
    assert findings[0]["title"] == "GitHub Personal Access Token"

    # Test fine-grained PAT
    lines = ["TOKEN = github_pat_1234567890123456789_123456789012345678901234567890123456789012345678901234567890123"]
    findings = list(detect(lines))
    assert len(findings) == 1

    # Test no match
    lines = ["API_TOKEN = not_a_token"]
    findings = list(detect(lines))
    assert len(findings) == 0


def test_aws_key_detector():
    """Test AWS Access Key detector patterns."""
    try:
        from src.services.agents.app.detectors.aws_keypair import detect
    except ImportError:
        from services.agents.app.detectors.aws_keypair import detect

    # Test Access Key ID
    lines = ["AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE"]
    findings = list(detect(lines))
    assert len(findings) == 1
    assert findings[0]["id"] == "aws_keypair"
    assert "AWS Access Key ID" in findings[0]["title"]

    # Test Secret Access Key (40 chars base64-like)
    lines = ["AWS_SECRET = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
    findings = list(detect(lines))
    assert len(findings) == 1

    # Test no match
    lines = ["AWS_REGION = us-east-1"]
    findings = list(detect(lines))
    assert len(findings) == 0