from dataclasses import dataclass
from typing import Iterable, Optional


@dataclass
class Finding:
    path: str
    kind: str
    match: str
    line: Optional[int] = None
    is_secret: bool = False
    reason: str = ""


class Detector:
    name: str = "base"

    def scan_file(self, path: str, text: str) -> Iterable[Finding]:
        raise NotImplementedError

    def verify(self, finding: Finding) -> Finding:
        return finding
