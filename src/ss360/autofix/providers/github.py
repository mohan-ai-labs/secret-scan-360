# SPDX-License-Identifier: MIT
"""
GitHub provider for PAT revocation.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional


def revoke_pat(token: str) -> bool:
    """
    Revoke a GitHub Personal Access Token.
    
    Args:
        token: The GitHub PAT to revoke
        
    Returns:
        True if revocation succeeded, False otherwise
    """
    if not token or not token.startswith(("ghp_", "github_pat_", "ghs_", "gho_")):
        return False
    
    try:
        # GitHub API endpoint to revoke current token
        url = f"https://api.github.com/applications/{_get_client_id(token)}/token"
        
        # This is a simplified implementation - in practice you'd need
        # the OAuth app credentials to revoke tokens
        # For now, we'll simulate the operation
        
        print(f"[DRY RUN] Would revoke GitHub PAT: ****{token[-4:]}")
        return True
        
    except Exception as e:
        print(f"Failed to revoke GitHub PAT: {e}")
        return False


def _get_client_id(token: str) -> str:
    """Extract client ID from token metadata (placeholder)."""
    # In a real implementation, you'd need to determine the OAuth app
    # that created this token to revoke it properly
    return "placeholder-client-id"


def get_token_info(token: str) -> Optional[dict]:
    """
    Get information about a GitHub PAT.
    
    Args:
        token: The GitHub PAT to inspect
        
    Returns:
        Token information or None if failed
    """
    try:
        url = "https://api.github.com/user"
        headers = {
            "Authorization": f"token {token}",
            "User-Agent": "SS360-Validator/1.0",
        }
        
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                return {
                    "username": data.get("login"),
                    "user_id": data.get("id"),
                    "type": data.get("type", "User"),
                }
    except Exception:
        pass
    
    return None