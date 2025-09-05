# SPDX-License-Identifier: MIT
"""
Tests for autofix framework.
"""
import pytest
from ss360.autofix.planner import AutofixPlanner, ActionType, PlanItem
from ss360.autofix.apply import AutofixApplier


class TestAutofixPlanner:
    """Test autofix plan generation."""
    
    def test_github_pat_planning(self):
        """Test planning for GitHub PAT findings."""
        planner = AutofixPlanner()
        
        findings = [
            {
                "id": "github_pat",
                "path": "config.py",
                "line": 10,
                "match": "ghp_1234567890123456789012345678901234567890",
                "risk_score": 75
            }
        ]
        
        plan = planner.generate_plan(findings)
        
        assert len(plan) == 2  # Remove literal + revoke token
        
        # Check remove literal action
        remove_action = next(item for item in plan if item.action == ActionType.REMOVE_LITERAL)
        assert remove_action.path == "config.py"
        assert remove_action.line == 10
        assert "secrets.GITHUB_TOKEN" in remove_action.replacement
        assert remove_action.reversible is True
        
        # Check revoke action
        revoke_action = next(item for item in plan if item.action == ActionType.REVOKE_TOKEN)
        assert revoke_action.provider == "github"
        assert revoke_action.reversible is False
    
    def test_aws_key_planning(self):
        """Test planning for AWS key findings."""
        planner = AutofixPlanner()
        
        findings = [
            {
                "id": "aws_keypair",
                "path": "deploy.sh",
                "line": 5,
                "match": "AKIAIOSFODNN7EXAMPLE",
                "risk_score": 80
            }
        ]
        
        plan = planner.generate_plan(findings)
        
        assert len(plan) == 2  # Replace + deactivate
        
        # Check replace action
        replace_action = next(item for item in plan if item.action == ActionType.REPLACE_WITH_SECRET_REF)
        assert "secretsmanager" in replace_action.replacement
        
        # Check deactivate action
        deactivate_action = next(item for item in plan if item.action == ActionType.DEACTIVATE_KEY)
        assert deactivate_action.provider == "aws"
        assert deactivate_action.reversible is True
    
    def test_risk_score_filtering(self):
        """Test that only high-risk findings get autofix plans."""
        planner = AutofixPlanner()
        
        # Low risk finding
        low_risk_findings = [
            {
                "id": "github_pat",
                "path": "test.py",
                "line": 1,
                "match": "ghp_fake",
                "risk_score": 30  # Below default threshold of 60
            }
        ]
        
        plan = planner.generate_plan(low_risk_findings)
        assert len(plan) == 0  # No autofix for low risk
        
        # High risk finding
        high_risk_findings = [
            {
                "id": "github_pat",
                "path": "prod.py", 
                "line": 1,
                "match": "ghp_real",
                "risk_score": 80  # Above threshold
            }
        ]
        
        plan = planner.generate_plan(high_risk_findings)
        assert len(plan) > 0  # Autofix planned


class TestAutofixApplier:
    """Test autofix plan application."""
    
    def test_dry_run_mode(self):
        """Test that dry run mode doesn't make actual changes."""
        applier = AutofixApplier(dry_run=True)
        
        plan_items = [
            PlanItem(
                action=ActionType.REMOVE_LITERAL,
                path="test.py",
                line=1,
                original_value="secret",
                replacement="${{ secrets.TEST }}",
                provider="test",
                reversible=True,
                description="Test action",
                safety_check="Safe"
            )
        ]
        
        result = applier.apply_plan(plan_items, confirmation_required=False)
        
        assert result["status"] == "success"
        assert len(result["applied"]) == 1
        assert result["applied"][0]["dry_run"] is True
    
    def test_revoke_token_dry_run(self):
        """Test token revocation in dry run mode."""
        applier = AutofixApplier(dry_run=True)
        
        plan_items = [
            PlanItem(
                action=ActionType.REVOKE_TOKEN,
                path="",
                line=0,
                original_value="ghp_1234567890123456789012345678901234567890",
                replacement="",
                provider="github",
                reversible=False,
                description="Revoke GitHub PAT",
                safety_check="Token will be revoked"
            )
        ]
        
        result = applier.apply_plan(plan_items, confirmation_required=False)
        
        assert result["status"] == "success"
        assert len(result["applied"]) == 1
        assert result["applied"][0]["action"] == "revoke_token"
        assert result["applied"][0]["dry_run"] is True