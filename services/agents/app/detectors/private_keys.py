import re
from .base import Detector, Finding

PEM_PATTERNS = [
    (r"-----BEGIN RSA PRIVATE KEY-----", "Private Key"),
    (r"-----BEGIN EC PRIVATE KEY-----", "Private Key"),
    (r"-----BEGIN OPENSSH PRIVATE KEY-----", "Private Key"),
]


class DetectorImpl(Detector):
    name = "private_keys"

    def scan_file(self, path: str, text: str):
        findings = []
        for pat, kind in PEM_PATTERNS:
            for m in re.finditer(pat, text):
                line = text.count("\\n", 0, m.start()) + 1
                findings.append(Finding(path=path, kind=kind, match=pat, line=line))
        return findings
