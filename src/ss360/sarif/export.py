from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Any


def build_sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("findings", []) or []
    root = str(report.get("root", ""))

    # Collect rules by 'kind'
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
        
        # Build result object with classification data
        result = {
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
        
        # Add classification properties if available
        if "category" in f or "confidence" in f or "reasons" in f:
            properties = {}
            if "category" in f:
                properties["category"] = f["category"]
            if "confidence" in f:
                properties["confidence"] = f["confidence"]  
            if "reasons" in f:
                properties["reasons"] = f["reasons"]
            
            result["properties"] = properties
        
        results.append(result)

    # Make this upload unique per job by setting automationDetails.id
    auto_id = "ss360-secrets-{run}-{job}-{attempt}".format(
        run=os.getenv("GITHUB_RUN_ID", "local"),
        job=os.getenv("GITHUB_JOB", "job"),
        attempt=os.getenv("GITHUB_RUN_ATTEMPT", "1"),
    )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "automationDetails": {"id": auto_id},
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