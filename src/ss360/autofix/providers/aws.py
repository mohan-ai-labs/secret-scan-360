from __future__ import annotations

from typing import Optional


def deactivate_access_key(ak_hint: Optional[str], evidence: Optional[str], *, allow_network: bool) -> bool:
    if not allow_network:
        return False
    # Safe stub for demo; real implementation would call AWS IAM without logging plaintext.
    return False
