import re
from .base import Detector, Finding

# Classic GH tokens start with ghp_, gho_, github_pat_ etc.
PAT = re.compile(r"(ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36,255}|github_pat_[0-9a-zA-Z_]{82,255}")


class DetectorImpl(Detector):
    name = "github_tokens"

    def scan_file(self, path: str, text: str):
        findings = []
        for m in PAT.finditer(text):
            line = text.count("\\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    path=path,
                    kind="GitHub Token",
                    match=m.group(0)[:20] + "...",
                    line=line,
                )
            )
        return findings
