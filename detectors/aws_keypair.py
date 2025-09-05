# SPDX-License-Identifier: MIT
"""
AWS Access Key detector.

Detects AWS Access Key IDs and Secret Access Keys.
"""
import re
from typing import Iterable, Dict, Iterator


# AWS Access Key patterns
PATTERNS = [
    # AWS Access Key ID: AKIA[0-9A-Z]{16}
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # AWS Secret Access Key: 40-character base64-like string
    re.compile(r"\b[A-Za-z0-9+/]{40}\b"),
    # Session tokens: longer base64 strings (384+ chars)
    re.compile(r"\b[A-Za-z0-9+/]{384,}\b"),
]


def detect(lines: Iterable[str]) -> Iterator[Dict[str, object]]:
    """
    Yield findings with line numbers when AWS key patterns match.
    """
    for i, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            match = pattern.search(line)
            if match:
                key_value = match.group(0)
                # Determine key type based on pattern
                if key_value.startswith("AKIA"):
                    key_type = "AWS Access Key ID"
                elif len(key_value) >= 384:
                    key_type = "AWS Session Token"
                else:
                    key_type = "AWS Secret Access Key"
                
                yield {
                    "id": "aws_keypair",
                    "title": key_type,
                    "severity": "high", 
                    "description": f"{key_type} detected",
                    "line": i,
                    "match": key_value,
                }
