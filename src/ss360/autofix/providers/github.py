from __future__ import annotations

from typing import Optional


def revoke_pat(
    token_hint: Optional[str], evidence: Optional[str], *, allow_network: bool
) -> bool:
    """
    Safe stub: return False if no network or insufficient evidence.
    In a fuller implementation, call GitHub API to revoke the token
    associated with the evidence (never logging plaintext).
    """
    if not allow_network:
        return False
    # Do not implement actual network I/O in demo stub.
    return False
