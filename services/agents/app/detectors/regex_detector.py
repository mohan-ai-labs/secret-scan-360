from __future__ import annotations
import re
from typing import Iterable, List, Dict, Any
from .base import Detector, Finding


class RegexDetector(Detector):
    """Configurable regex-based detector.

    rules: List[dict] with keys:
      - name: str (human label)
      - kind: str (Finding.kind)
      - pattern: str (compiled)
      - redact: bool (default True)
    """

    def __init__(self, rules: List[Dict[str, Any]]) -> None:
        compiled = []
        for r in rules or []:
            pat = r.get("pattern")
            if pat is None:
                continue
            compiled.append(
                {
                    "name": r.get("name", "unnamed-rule"),
                    "kind": r.get("kind", "Generic"),
                    "pattern": re.compile(pat),
                    "redact": bool(r.get("redact", True)),
                }
            )
        self._rules = compiled

    @property
    def name(self) -> str:
        return "regex"

    def detect(self, path: str, text: str) -> Iterable[Finding]:
        if not text:
            return []
        findings = []
        for rule in self._rules:
            for m in rule["pattern"].finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                raw = m.group(0)
                shown = (raw[:4] + "…" + raw[-4:]) if rule["redact"] and len(raw) > 12 else raw
                findings.append(
                    Finding(
                        path=path,
                        kind=rule["kind"],
                        match=shown,
                        line=line,
                        is_secret=True,
                        reason=f"Matched rule: {rule['name']}",
                    )
                )
        return findings
