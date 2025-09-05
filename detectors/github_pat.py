# SPDX-License-Identifier: MIT
"""
GitHub Personal Access Token detector.

Detects GitHub PATs using pattern matching.
"""
import re
from typing import Iterable, Dict, Iterator


# GitHub PAT patterns - covers classic, fine-grained, and app tokens
PATTERNS = [
    # Classic PATs: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (40 chars after ghp_)
    re.compile(r"\bghp_[A-Za-z0-9]{40}\b"),
    # Fine-grained PATs: github_pat_xxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b"),
    # GitHub App tokens: ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (40 chars after ghs_)
    re.compile(r"\bghs_[A-Za-z0-9]{40}\b"),
    # OAuth tokens: gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (40 chars after gho_)
    re.compile(r"\bgho_[A-Za-z0-9]{40}\b"),
]


def detect(lines: Iterable[str]) -> Iterator[Dict[str, object]]:
    """
    Yield findings with line numbers when GitHub PAT patterns match.
    """
    for i, line in enumerate(lines, start=1):
        for pattern in PATTERNS:
            if pattern.search(line):
                yield {
                    "id": "github_pat",
                    "title": "GitHub Personal Access Token",
                    "severity": "high",
                    "description": "GitHub Personal Access Token detected",
                    "line": i,
                    "match": pattern.search(line).group(0),
                }
