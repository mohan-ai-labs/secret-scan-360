"""Finding data structures and utilities for Secret Scan 360."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass(frozen=True)
class Finding:
    """Represents a secret or sensitive finding in a file."""
    
    path: str  # repo-relative file path
    rule: str  # detector rule name (e.g., 'github_pat', 'aws_keypair')
    line: int  # 1-based line number
    match_hint: str  # redacted snippet that triggered detection
    severity: str  # severity level (e.g., 'high', 'medium', 'low')
    reason: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_match(
        cls,
        rule: str,
        path: str,
        line: int,
        match_hint: str,
        severity: str,
        reason: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> "Finding":
        """Create a Finding from match details."""
        return cls(
            path=path,
            rule=rule,
            line=line,
            match_hint=match_hint,
            severity=severity,
            reason=reason,
            meta=meta,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Finding to dictionary format."""
        result = {
            "id": self.rule,
            "path": self.path,
            "line": self.line,
            "match": self.match_hint,
            "severity": self.severity,
        }
        
        if self.reason:
            result["reason"] = self.reason
            
        if self.meta:
            result["meta"] = self.meta
            
        return result