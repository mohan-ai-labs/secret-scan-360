from __future__ import annotations
import re
from typing import List
from ss360.core.findings import Finding

NAME = "github_pat"
SEVERITY = "high"

# Match both:
#  - classic: ghp_<36 alnum>
#  - fine-grained: github_pat_<id/variant with underscores> (length varies)
GITHUB_PAT_RE = re.compile(
    r"(?P<token>(?:ghp_[A-Za-z0-9]{36}|github_pat_[0-9A-Za-z_]{22,255}))"
)

def scan(blob: bytes, path: str) -> List[Finding]:
    text = blob.decode(errors="ignore")
    out: List[Finding] = []
    for m in GITHUB_PAT_RE.finditer(text):
        token = m.group("token")
        # compute line number for nicer output
        line = text[: m.start()].count("\n") + 1
        # redact: first 6 and last 4 only
        hint = f"{token[:6]}...{token[-4:]}"
        out.append(
            Finding.from_match(
                rule=NAME,
                path=path,
                line=line,
                match_hint=hint,
                severity=SEVERITY,
            )
        )
    return out