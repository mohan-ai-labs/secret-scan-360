from __future__ import annotations

from typing import Optional


def revoke_pat(token_hint: Optional[str], evidence: Optional[str], *, allow_network: bool) -> bool:
    if not allow_network:
        return False
    # Safe stub for demo; real implementation would call GitHub API without logging plaintext.
    return False
