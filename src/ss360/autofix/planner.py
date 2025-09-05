# SPDX-License-Identifier: MIT
"""
Autofix planner - generates remediation plans for security findings.
"""
from __future__ import annotations

from typing import Dict, Any, List
from dataclasses import dataclass
from enum import Enum


class ActionType(Enum):
    """Types of autofix actions."""
    REMOVE_LITERAL = "remove_literal"
    REPLACE_WITH_SECRET_REF = "replace_with_secret_ref"
    REVOKE_TOKEN = "revoke_token" 
    DEACTIVATE_KEY = "deactivate_key"
    ADD_SECRET_TO_VAULT = "add_secret_to_vault"


@dataclass
class PlanItem:
    """A single item in an autofix plan."""
    action: ActionType
    path: str
    line: int
    original_value: str  # Will be redacted in output
    replacement: str
    provider: str
    reversible: bool
    description: str
    safety_check: str


class AutofixPlanner:
    """Generates autofix plans for security findings."""
    
    def __init__(self):
        self.providers = {
            "github_pat": "github",
            "aws_keypair": "aws",
        }
    
    def generate_plan(
        self,
        findings: List[Dict[str, Any]],
        policy_config: Dict[str, Any] = None,
        dry_run: bool = True
    ) -> List[PlanItem]:
        """
        Generate an autofix plan for the given findings.
        
        Args:
            findings: List of security findings
            policy_config: Policy configuration
            dry_run: If True, only plan without executing
            
        Returns:
            List of planned autofix actions
        """
        policy_config = policy_config or {}
        plan_items = []
        
        for finding in findings:
            finding_id = finding.get("id", "")
            risk_score = finding.get("risk_score", 0)
            
            # Only plan fixes for confirmed high-risk findings
            if risk_score < policy_config.get("min_autofix_risk_score", 60):
                continue
                
            if finding_id == "github_pat":
                plan_items.extend(self._plan_github_pat_fix(finding))
            elif finding_id == "aws_keypair":
                plan_items.extend(self._plan_aws_key_fix(finding))
        
        return plan_items
    
    def _plan_github_pat_fix(self, finding: Dict[str, Any]) -> List[PlanItem]:
        """Plan fixes for GitHub PAT findings."""
        items = []
        path = finding.get("path", "")
        line = finding.get("line", 0)
        token = finding.get("match", "")
        
        # Remove literal token from code
        items.append(PlanItem(
            action=ActionType.REMOVE_LITERAL,
            path=path,
            line=line,
            original_value=token,
            replacement="${{ secrets.GITHUB_TOKEN }}",
            provider="github",
            reversible=True,
            description=f"Replace GitHub PAT literal with secret reference in {path}:{line}",
            safety_check="Token will be revoked after replacement"
        ))
        
        # Revoke the token
        items.append(PlanItem(
            action=ActionType.REVOKE_TOKEN,
            path="",
            line=0,
            original_value=token,
            replacement="",
            provider="github",
            reversible=False,
            description=f"Revoke GitHub PAT ****{token[-4:]} via API",
            safety_check="Token revocation cannot be undone"
        ))
        
        return items
    
    def _plan_aws_key_fix(self, finding: Dict[str, Any]) -> List[PlanItem]:
        """Plan fixes for AWS Access Key findings."""
        items = []
        path = finding.get("path", "")
        line = finding.get("line", 0)
        key = finding.get("match", "")
        
        if key.startswith("AKIA"):
            # Replace access key with Secrets Manager reference
            items.append(PlanItem(
                action=ActionType.REPLACE_WITH_SECRET_REF,
                path=path,
                line=line,
                original_value=key,
                replacement="{{resolve:secretsmanager:aws-access-keys:SecretString:AccessKeyId}}",
                provider="aws",
                reversible=True,
                description=f"Replace AWS Access Key with Secrets Manager reference in {path}:{line}",
                safety_check="Key will be deactivated after replacement"
            ))
            
            # Deactivate the access key
            items.append(PlanItem(
                action=ActionType.DEACTIVATE_KEY,
                path="",
                line=0,
                original_value=key,
                replacement="",
                provider="aws",
                reversible=True,
                description=f"Deactivate AWS Access Key ****{key[-4:]} via IAM API",
                safety_check="Key can be reactivated if needed"
            ))
        
        return items


def format_plan_for_display(plan_items: List[PlanItem]) -> str:
    """Format plan items for human-readable display."""
    if not plan_items:
        return "No autofix actions planned."
    
    output = ["Autofix Plan:", "=" * 40, ""]
    
    for i, item in enumerate(plan_items, 1):
        output.extend([
            f"{i}. {item.description}",
            f"   Action: {item.action.value}",
            f"   File: {item.path}:{item.line}" if item.path else "",
            f"   Provider: {item.provider}",
            f"   Reversible: {'Yes' if item.reversible else 'No'}",
            f"   Safety: {item.safety_check}",
            ""
        ])
    
    return "\n".join(line for line in output if line is not None)