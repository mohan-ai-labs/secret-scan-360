from __future__ import annotations

from typing import Optional


def deactivate_access_key(ak_hint: Optional[str], evidence: Optional[str], *, allow_network: bool) -> bool:
    """
    Safe stub: return False if no network or insufficient evidence.
    In a fuller implementation, call AWS IAM to deactivate the access key.
    """
    if not allow_network:
        return False
    # Do not implement actual network I/O in demo stub.
    return False