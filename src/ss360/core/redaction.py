# SPDX-License-Identifier: MIT
"""
Central redaction utilities for SS360.

This module provides consistent redaction across all outputs including
JSON, SARIF, console, and validator evidence.
"""

from __future__ import annotations
import re
from typing import Dict, Any, Union, List


def redact_secret(secret: str) -> str:
    """
    Redact secret showing first 6 + last 4 characters.
    
    For secrets <= 10 characters, shows only ****.
    For secrets > 10 characters, shows first6****last4.
    
    Args:
        secret: The secret string to redact
        
    Returns:
        Redacted string
    """
    if len(secret) <= 10:
        return "****"
    return secret[:6] + "****" + secret[-4:]


def redact_evidence_string(evidence: str) -> str:
    """
    Redact secrets in evidence strings showing first 6 + last 4 chars only.
    
    Args:
        evidence: Evidence string that may contain secrets
        
    Returns:
        Evidence string with secrets redacted
    """
    lines = evidence.split("\n")
    redacted_lines = []

    for line in lines:
        # Look for patterns that might be secrets (longer alphanumeric strings
        # with underscores, plus, slashes, dashes)
        redacted_line = re.sub(
            r"\b[A-Za-z0-9+/_-]{16,}\b",  # Match secrets 16+ chars
            lambda m: redact_secret(m.group(0)),
            line,
        )
        redacted_lines.append(redacted_line)

    return "\n".join(redacted_lines)


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact secrets in a finding dictionary.
    
    Args:
        finding: Finding dictionary that may contain secrets
        
    Returns:
        Finding dictionary with secrets redacted
    """
    redacted_finding = finding.copy()
    
    # Redact the match field if present
    if "match" in redacted_finding and isinstance(redacted_finding["match"], str):
        redacted_finding["match"] = redact_secret(redacted_finding["match"])
    
    # Redact match_hint field if present
    if "match_hint" in redacted_finding and isinstance(redacted_finding["match_hint"], str):
        redacted_finding["match_hint"] = redact_secret(redacted_finding["match_hint"])
    
    # Redact any evidence in validator results
    if "validators" in redacted_finding and isinstance(redacted_finding["validators"], dict):
        validators = redacted_finding["validators"].copy()
        if "results" in validators:
            results = validators["results"].copy()
            for key, validator_results in results.items():
                if isinstance(validator_results, list):
                    redacted_results = []
                    for result in validator_results:
                        if isinstance(result, dict) and "evidence" in result:
                            redacted_result = result.copy()
                            if isinstance(result["evidence"], str):
                                redacted_result["evidence"] = redact_evidence_string(result["evidence"])
                            redacted_results.append(redacted_result)
                        else:
                            redacted_results.append(result)
                    results[key] = redacted_results
            validators["results"] = results
        redacted_finding["validators"] = validators
    
    return redacted_finding


def redact_findings_list(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Redact secrets in a list of findings.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        List of finding dictionaries with secrets redacted
    """
    return [redact_finding(finding) for finding in findings]


def redact_scan_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact secrets in a complete scan result.
    
    Args:
        result: Scan result dictionary
        
    Returns:
        Scan result dictionary with secrets redacted
    """
    redacted_result = result.copy()
    
    # Redact findings if present
    if "findings" in redacted_result and isinstance(redacted_result["findings"], list):
        redacted_result["findings"] = redact_findings_list(redacted_result["findings"])
    
    return redacted_result