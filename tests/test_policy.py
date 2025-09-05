# SPDX-License-Identifier: MIT
"""
Tests for policy enforcement.
"""
import pytest
from datetime import datetime, timedelta
from ss360.policy.loader import load_policy_config, get_default_policy_config, is_waiver_active
from ss360.policy.enforce import PolicyEnforcer, PolicyViolationType


class TestPolicyLoader:
    """Test policy configuration loading."""
    
    def test_default_policy_config(self):
        """Test default policy configuration."""
        config = get_default_policy_config()
        
        assert config["version"] == 1
        assert config["validators"]["allow_network"] is False
        assert config["validators"]["global_qps"] == 2.0
        assert config["budgets"]["new_findings"] == 0
        assert config["budgets"]["max_risk_score"] == 40
        assert isinstance(config["waivers"], list)
    
    def test_waiver_matching(self):
        """Test waiver matching logic."""
        # Active waiver
        future_date = (datetime.now() + timedelta(days=30)).isoformat()
        waiver = {
            "rule": "github_pat",
            "path": "tests/**/*",
            "expiry": future_date,
            "reason": "Test fixtures"
        }
        
        assert is_waiver_active(waiver, "tests/test_auth.py", "github_pat") is True
        assert is_waiver_active(waiver, "src/main.py", "github_pat") is False
        assert is_waiver_active(waiver, "tests/test_auth.py", "aws_keypair") is False
        
        # Expired waiver
        past_date = (datetime.now() - timedelta(days=1)).isoformat()
        expired_waiver = {
            "rule": "github_pat",
            "path": "tests/**/*",
            "expiry": past_date,
            "reason": "Expired"
        }
        
        assert is_waiver_active(expired_waiver, "tests/test_auth.py", "github_pat") is False


class TestPolicyEnforcer:
    """Test policy enforcement."""
    
    def test_budget_violations(self):
        """Test budget violation detection."""
        policy_config = {
            "version": 1,
            "validators": {"allow_network": False, "global_qps": 2.0},
            "budgets": {"new_findings": 0, "max_risk_score": 40},
            "waivers": []
        }
        
        enforcer = PolicyEnforcer(policy_config)
        
        findings = [
            {"id": "github_pat", "path": "config.py", "line": 10, "risk_score": 30}
        ]
        
        result = enforcer.enforce(findings)
        
        # Should violate new_findings budget (max 0, found 1)
        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].type == PolicyViolationType.BUDGET_EXCEEDED
    
    def test_risk_score_violations(self):
        """Test risk score violation detection."""
        policy_config = {
            "version": 1,
            "validators": {"allow_network": False, "global_qps": 2.0},
            "budgets": {"new_findings": 1, "max_risk_score": 40},
            "waivers": []
        }
        
        enforcer = PolicyEnforcer(policy_config)
        
        findings = [
            {"id": "github_pat", "path": "config.py", "line": 10, "risk_score": 60}
        ]
        
        result = enforcer.enforce(findings)
        
        # Should violate max_risk_score (max 40, found 60)
        assert result.passed is False
        assert len(result.violations) == 1
        assert result.violations[0].type == PolicyViolationType.RISK_SCORE_TOO_HIGH
    
    def test_waivers_applied(self):
        """Test that waivers prevent policy violations."""
        future_date = (datetime.now() + timedelta(days=30)).isoformat()
        policy_config = {
            "version": 1,
            "validators": {"allow_network": False, "global_qps": 2.0},
            "budgets": {"new_findings": 0, "max_risk_score": 40},
            "waivers": [
                {
                    "rule": "github_pat",
                    "path": "tests/**/*",
                    "expiry": future_date,
                    "reason": "Test fixtures"
                }
            ]
        }
        
        enforcer = PolicyEnforcer(policy_config)
        
        findings = [
            {"id": "github_pat", "path": "tests/test_auth.py", "line": 10, "risk_score": 60}
        ]
        
        result = enforcer.enforce(findings)
        
        # Should pass because waiver applies
        assert result.passed is True
        assert len(result.waivers_applied) == 1
        assert len(result.violations) == 0
    
    def test_no_violations(self):
        """Test case with no policy violations."""
        policy_config = {
            "version": 1,
            "validators": {"allow_network": False, "global_qps": 2.0},
            "budgets": {"new_findings": 5, "max_risk_score": 80},
            "waivers": []
        }
        
        enforcer = PolicyEnforcer(policy_config)
        
        findings = [
            {"id": "github_pat", "path": "config.py", "line": 10, "risk_score": 30}
        ]
        
        result = enforcer.enforce(findings)
        
        assert result.passed is True
        assert len(result.violations) == 0