import re
from .base import Detector, Finding

AKID = re.compile(r"AKIA[0-9A-Z]{16}")
SAKEY = re.compile(r"(?i)aws(.{0,20})?(secret|sk|access)[^a-zA-Z0-9]{0,3}([0-9a-zA-Z/+]{40})")


class DetectorImpl(Detector):
    name = "aws_keys"

    def scan_file(self, path: str, text: str):
        findings = []
        for m in AKID.finditer(text):
            line = text.count("\\n", 0, m.start()) + 1
            findings.append(Finding(path=path, kind="AWS Access Key", match=m.group(0), line=line))
        for m in SAKEY.finditer(text):
            line = text.count("\\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    path=path,
                    kind="AWS Secret Key",
                    match=m.group(0)[:16] + "...",
                    line=line,
                )
            )
        return findings
