# SPDX-License-Identifier: MIT
"""
Live validators for GitHub PAT and AWS Access Keys.

These validators make network calls to verify if credentials are valid.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Dict, Any
from .core import ValidationResult, ValidationState, _redact_secret


class GitHubPATLiveValidator:
    """Validator that checks GitHub PAT validity via API."""

    name = "github_pat_live"
    rate_limit_qps = 1.0  # Conservative rate limit
    requires_network = True

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate GitHub PAT by checking token scopes.

        Args:
            finding: Finding containing the GitHub PAT

        Returns:
            ValidationResult with state and redacted evidence
        """
        token = finding.get("match", "")
        if not token or not token.startswith(("ghp_", "github_pat_", "ghs_", "gho_")):
            return ValidationResult(
                state=ValidationState.INVALID,
                reason="Invalid GitHub PAT format",
                validator_name=self.name,
            )

        try:
            # GitHub API endpoint to check token
            url = "https://api.github.com/user"
            headers = {
                "Authorization": f"token {token}",
                "User-Agent": "SS360-Validator/1.0",
            }

            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode())
                    username = data.get("login", "unknown")
                    # Use redacted username for evidence
                    redacted_username = _redact_secret(username) if len(username) > 10 else username
                    return ValidationResult(
                        state=ValidationState.VALID,
                        evidence=f"Valid GitHub token for user: {redacted_username}",
                        reason="Token successfully authenticated with GitHub API",
                        validator_name=self.name,
                    )
                else:
                    return ValidationResult(
                        state=ValidationState.INVALID,
                        reason=f"GitHub API returned status {response.status}",
                        validator_name=self.name,
                    )

        except urllib.error.HTTPError as e:
            if e.code == 401:
                return ValidationResult(
                    state=ValidationState.INVALID,
                    reason="Token rejected by GitHub API (401 Unauthorized)",
                    validator_name=self.name,
                )
            else:
                return ValidationResult(
                    state=ValidationState.INDETERMINATE,
                    reason=f"GitHub API error: {e.code}",
                    validator_name=self.name,
                )
        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"Network error: {str(e)}",
                validator_name=self.name,
            )


class AWSAccessKeyLiveValidator:
    """Validator that checks AWS Access Key validity via STS."""

    name = "aws_ak_live"
    rate_limit_qps = 0.5  # More conservative for AWS
    requires_network = True

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate AWS Access Key by attempting STS GetCallerIdentity.

        Args:
            finding: Finding containing the AWS Access Key

        Returns:
            ValidationResult with state and redacted evidence
        """
        key_id = finding.get("match", "")
        if not key_id or not key_id.startswith("AKIA"):
            return ValidationResult(
                state=ValidationState.INVALID,
                reason="Invalid AWS Access Key ID format",
                validator_name=self.name,
            )

        try:
            # Basic format validation first
            if len(key_id) != 20 or not key_id.startswith("AKIA"):
                return ValidationResult(
                    state=ValidationState.INVALID,
                    reason="Invalid AWS Access Key ID format",
                    validator_name=self.name,
                )

            # For live validation, we would need both access key and secret key
            # Since we typically only detect the access key ID, we can't perform 
            # a full STS call without the secret. However, we can check if sandbox
            # credentials are provided in the config for testing purposes.
            
            # Check if we have test credentials in the finding context
            secret_key = finding.get("aws_secret_key")  # Could be provided for testing
            if secret_key:
                return self._validate_with_sts(key_id, secret_key)
            else:
                # Without secret key, we can only validate format
                redacted_key = _redact_secret(key_id)
                return ValidationResult(
                    state=ValidationState.INDETERMINATE,
                    reason="AWS Access Key ID format valid, but full validation requires secret key",
                    evidence=f"Valid AKIA format: {redacted_key}",
                    validator_name=self.name,
                )

        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"Validation error: {str(e)}",
                validator_name=self.name,
            )

    def _validate_with_sts(self, access_key: str, secret_key: str) -> ValidationResult:
        """Attempt STS GetCallerIdentity with provided credentials."""
        try:
            # For a real implementation, this would:
            # 1. Use AWS Signature Version 4 to sign the request
            # 2. Make a request to https://sts.amazonaws.com/
            # 3. Check if the credentials are valid
            # 
            # This is a simplified mock that just validates the format
            # and returns indeterminate since implementing AWS sig v4 is complex
            
            redacted_key = _redact_secret(access_key)
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                evidence=f"AWS credentials format valid: {redacted_key}",
                reason="Format validation passed, but STS validation requires full AWS signature implementation",
                validator_name=self.name,
            )
            
        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"STS validation error: {str(e)}",
                validator_name=self.name,
            )
