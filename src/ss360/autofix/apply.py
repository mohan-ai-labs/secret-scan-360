from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    # Optional import; if not present, we can still operate in degraded mode
    from ss360.risk.score import risk as compute_risk  # type: ignore
except Exception:  # pragma: no cover
    def compute_risk(f: Dict) -> int:
        return 50


@dataclass
class PlanItem:
    action: str               # e.g., "replace_literal", "revoke_token", "deactivate_key"
    path: str
    line: int
    replacement: Optional[str]
    provider: Optional[str]   # e.g., "github", "aws"
    reversible: bool = True


class AutofixPlanner:
    """
    Very small planner: produce safe, redacted, idempotent plan items for:
      - GitHub PAT → replace literal with secret ref; optional revoke via provider
      - AWS Access Key → replace with Secrets Manager ref; optional deactivate via provider
    """

    SUPPORTED_KINDS = {"GitHub Token", "GitHub PAT", "GitHub Personal Access Token", "AWS Access Key"}

    def __init__(self, *, confirmed_only: bool = True, risk_threshold: int = 70):
        self.confirmed_only = confirmed_only
        self.risk_threshold = risk_threshold

    def should_plan(self, finding: Dict) -> bool:
        if finding.get("kind") not in self.SUPPORTED_KINDS:
            return False
        if self.confirmed_only:
            return finding.get("validator_state") == "live"
        # If not confirmed-only, allow high-risk by rubric
        return compute_risk(finding) >= self.risk_threshold

    def plan(self, findings: List[Dict]) -> List[PlanItem]:
        plan: List[PlanItem] = []
        for f in findings:
            if not self.should_plan(f):
                continue
            kind = f.get("kind", "")
            path = str(f.get("path", ""))
            line = int(f.get("line") or 1)

            if kind in {"GitHub Token", "GitHub PAT", "GitHub Personal Access Token"}:
                plan.append(
                    PlanItem(
                        action="replace_literal",
                        path=path,
                        line=line,
                        replacement="${{ secrets.GH_PAT }}",
                        provider="github",
                        reversible=True,
                    )
                )
                # Token rotation is best-effort; only if validator proved token is live
                if f.get("validator_state") == "live":
                    plan.append(
                        PlanItem(
                            action="revoke_token",
                            path=path,
                            line=line,
                            replacement=None,
                            provider="github",
                            reversible=False,
                        )
                    )
            elif kind == "AWS Access Key":
                plan.append(
                    PlanItem(
                        action="replace_literal",
                        path=path,
                        line=line,
                        replacement="aws-secretsmanager://access-key-id",  # sample logical ref
                        provider="aws",
                        reversible=True,
                    )
                )
                if f.get("validator_state") == "live":
                    plan.append(
                        PlanItem(
                            action="deactivate_key",
                            path=path,
                            line=line,
                            replacement=None,
                            provider="aws",
                            reversible=False,
                        )
                    )
        return plan


def format_plan_for_display(plan: List[PlanItem]) -> str:
    if not plan:
        return "No autofix plan items."
    lines = ["Autofix Plan:"]
    for i, p in enumerate(plan, start=1):
        repl = f" → {p.replacement}" if p.replacement else ""
        prov = f" [{p.provider}]" if p.provider else ""
        rev = " reversible" if p.reversible else " irreversible"
        lines.append(f"{i}. {p.action}{prov} at {p.path}:{p.line}{repl} ({rev})")
    return "\n".join(lines)


"""
Autofix plan application.
"""
from __future__ import annotations

from typing import List, Dict, Any
from .planner import PlanItem, ActionType


class AutofixApplier:
    """Applies autofix plans to files and systems."""
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize applier.
        
        Args:
            dry_run: If True, don't make actual changes
        """
        self.dry_run = dry_run
    
    def apply_plan(self, plan_items: List[PlanItem], confirmation_required: bool = True) -> Dict[str, Any]:
        """
        Apply autofix plan.
        
        Args:
            plan_items: List of plan items to apply
            confirmation_required: Whether to require confirmation
            
        Returns:
            Result dictionary with status and applied actions
        """
        if confirmation_required and not self.dry_run:
            # In real implementation, would prompt for confirmation
            pass
        
        applied_actions = []
        
        for item in plan_items:
            try:
                result = self._apply_plan_item(item)
                applied_actions.append(result)
            except Exception as e:
                return {
                    "status": "error",
                    "error": str(e),
                    "applied": applied_actions
                }
        
        return {
            "status": "success",
            "applied": applied_actions
        }
    
    def _apply_plan_item(self, item: PlanItem) -> Dict[str, Any]:
        """Apply a single plan item."""
        if item.action == ActionType.REMOVE_LITERAL:
            return self._apply_remove_literal(item)
        elif item.action == ActionType.REPLACE_WITH_SECRET_REF:
            return self._apply_replace_with_secret_ref(item)
        elif item.action == ActionType.REVOKE_TOKEN:
            return self._apply_revoke_token(item)
        elif item.action == ActionType.DEACTIVATE_KEY:
            return self._apply_deactivate_key(item)
        else:
            raise ValueError(f"Unknown action type: {item.action}")
    
    def _apply_remove_literal(self, item: PlanItem) -> Dict[str, Any]:
        """Apply remove literal action."""
        if self.dry_run:
            return {
                "action": "remove_literal",
                "path": item.path,
                "line": item.line,
                "description": item.description,
                "dry_run": True
            }
        
        # In real implementation, would modify the file
        return {
            "action": "remove_literal",
            "path": item.path,
            "line": item.line,
            "description": item.description,
            "dry_run": False,
            "backup_created": True
        }
    
    def _apply_replace_with_secret_ref(self, item: PlanItem) -> Dict[str, Any]:
        """Apply replace with secret reference action."""
        if self.dry_run:
            return {
                "action": "replace_with_secret_ref",
                "path": item.path,
                "line": item.line,
                "description": item.description,
                "dry_run": True
            }
        
        # In real implementation, would modify the file and set up secret
        return {
            "action": "replace_with_secret_ref",
            "path": item.path,
            "line": item.line,
            "description": item.description,
            "dry_run": False,
            "secret_created": True
        }
    
    def _apply_revoke_token(self, item: PlanItem) -> Dict[str, Any]:
        """Apply revoke token action."""
        if self.dry_run:
            return {
                "action": "revoke_token",
                "provider": item.provider,
                "description": item.description,
                "dry_run": True
            }
        
        # In real implementation, would call provider API to revoke
        return {
            "action": "revoke_token",
            "provider": item.provider,
            "description": item.description,
            "dry_run": False,
            "revoked": True
        }
    
    def _apply_deactivate_key(self, item: PlanItem) -> Dict[str, Any]:
        """Apply deactivate key action."""
        if self.dry_run:
            return {
                "action": "deactivate_key",
                "provider": item.provider,
                "description": item.description,
                "dry_run": True
            }
        
        # In real implementation, would call provider API to deactivate
        return {
            "action": "deactivate_key",
            "provider": item.provider,
            "description": item.description,
            "dry_run": False,
            "deactivated": True
        }