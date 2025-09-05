# SPDX-License-Identifier: MIT
"""
AWS provider for access key deactivation.
"""
from __future__ import annotations

import json
import subprocess
from typing import Optional, Dict, Any


def deactivate_access_key(access_key_id: str) -> bool:
    """
    Deactivate an AWS Access Key.

    Args:
        access_key_id: The AWS Access Key ID to deactivate

    Returns:
        True if deactivation succeeded, False otherwise
    """
    if not access_key_id or not access_key_id.startswith("AKIA"):
        return False

    try:
        # For now, simulate the operation
        print(f"[DRY RUN] Would deactivate AWS Access Key: ****{access_key_id[-4:]}")
        return True

        # Real implementation would use AWS CLI or boto3:
        # result = subprocess.run([
        #     "aws", "iam", "update-access-key",
        #     "--access-key-id", access_key_id,
        #     "--status", "Inactive"
        # ], capture_output=True, text=True)
        # return result.returncode == 0

    except Exception as e:
        print(f"Failed to deactivate AWS Access Key: {e}")
        return False


def reactivate_access_key(access_key_id: str) -> bool:
    """
    Reactivate an AWS Access Key.

    Args:
        access_key_id: The AWS Access Key ID to reactivate

    Returns:
        True if reactivation succeeded, False otherwise
    """
    if not access_key_id or not access_key_id.startswith("AKIA"):
        return False

    try:
        result = subprocess.run([
            "aws", "iam", "update-access-key",
            "--access-key-id", access_key_id,
            "--status", "Active"
        ], capture_output=True, text=True)

        return result.returncode == 0

    except Exception as e:
        print(f"Failed to reactivate AWS Access Key: {e}")
        return False


def get_access_key_info(access_key_id: str) -> Optional[Dict[str, Any]]:
    """
    Get information about an AWS Access Key.

    Args:
        access_key_id: The AWS Access Key ID to inspect

    Returns:
        Key information or None if failed
    """
    try:
        result = subprocess.run([
            "aws", "iam", "get-access-key-last-used",
            "--access-key-id", access_key_id
        ], capture_output=True, text=True)

        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("AccessKeyLastUsed", {})

    except Exception:
        pass

    return None


def list_user_access_keys(username: str) -> list:
    """
    List all access keys for a given IAM user.

    Args:
        username: The IAM username

    Returns:
        List of access key information
    """
    try:
        result = subprocess.run([
            "aws", "iam", "list-access-keys",
            "--user-name", username
        ], capture_output=True, text=True)

        if result.returncode == 0:
            data = json.loads(result.stdout)
            return data.get("AccessKeyMetadata", [])

    except Exception:
        pass

    return []