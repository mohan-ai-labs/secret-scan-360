from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

try:
    from ss360.risk.score import risk as compute_risk  # type: ignore
except Exception:  # pragma: no cover

    def compute_risk(f: Dict) -> int:
        return 50


@dataclass
class PlanItem:
    action: str  # "replace_literal" | "revoke_token" | "deactivate_key"
    path: str
    line: int
    replacement: Optional[str]
    provider: Optional[str]  # "github" | "aws" | None
    reversible: bool = True


class AutofixPlanner:
    SUPPORTED_KINDS = {
        "GitHub Token",
        "GitHub PAT",
        "GitHub Personal Access Token",
        "AWS Access Key",
    }

    def __init__(self, *, confirmed_only: bool = True, risk_threshold: int = 70):
        self.confirmed_only = confirmed_only
        self.risk_threshold = risk_threshold

    def should_plan(self, finding: Dict) -> bool:
        if finding.get("kind") not in self.SUPPORTED_KINDS:
            return False
        if self.confirmed_only:
            return finding.get("validator_state") == "live"
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
                        replacement="aws-secretsmanager://access-key-id",
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
