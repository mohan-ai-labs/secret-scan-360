from __future__ import annotations

from pathlib import Path
from typing import Dict, Any


def build_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("findings", []) or []
    root = str(report.get("root", ""))

    rule_ids = {}
    rules = []
    for f in findings:
        k = f.get("kind", "Unknown")
        if k not in rule_ids:
            rule_ids[k] = len(rules)
            rules.append(
                {
                    "id": k,
                    "name": k,
                    "shortDescription": {"text": f"SS360 rule: {k}"},
                    "fullDescription": {"text": f"Findings of kind {k}"},
                    "helpUri": "https://github.com/mohan-ai-labs/secret-scan-360",
                }
            )

    results = []
    for f in findings:
        k = f.get("kind", "Unknown")
        ridx = rule_ids.get(k, 0)
        path = str(f.get("path", ""))
        line = int(f.get("line") or 1)
        reason = f.get("reason") or k
        try:
            p_rel = str(Path(path).resolve().relative_to(Path(root).resolve()))
        except Exception:
            p_rel = path
        level = "error" if bool(f.get("is_secret", True)) else "warning"
        results.append(
            {
                "ruleId": k,
                "ruleIndex": ridx,
                "level": level,
                "message": {"text": reason},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": p_rel},
                            "region": {"startLine": max(1, line)},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SS360",
                        "informationUri": "https://github.com/mohan-ai-labs/secret-scan-360",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
