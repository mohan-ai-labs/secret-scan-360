from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, Dict, Iterable
from abc import ABC, abstractmethod


@dataclass(frozen=True)
class Finding:
    path: str  # repo-relative file path
    kind: str  # e.g. "Private Key", "AWS Access Key"
    match: str  # short/redacted snippet that triggered detection
    line: int  # 1-based line number
    is_secret: bool  # detector's judgment
    reason: Optional[str] = None
    meta: Optional[Dict[str, str]] = None


class Detector(ABC):
    """Base class for all detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique detector name (e.g., 'regex', 'aws_keys')."""

    @abstractmethod
    def detect(self, path: str, text: str) -> Iterable[Finding]:
        """Inspect the given text and yield zero or more findings."""
