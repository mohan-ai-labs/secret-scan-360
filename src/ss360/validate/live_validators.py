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
from .core import ValidationResult, ValidationState


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
                    return ValidationResult(
                        state=ValidationState.VALID,
                        evidence=f"Valid GitHub token for user: {username}",
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
            # AWS STS GetCallerIdentity endpoint
            # Note: This is a simplified implementation - in practice you'd need
            # AWS signature v4 signing which requires the secret key too
            # For now, we'll just validate the format and return indeterminate
            # A full implementation would use boto3 or implement AWS sig v4

            if len(key_id) == 20 and key_id.startswith("AKIA"):
                return ValidationResult(
                    state=ValidationState.INDETERMINATE,
                    reason="AWS Access Key ID format valid, but full validation requires secret key",
                    evidence=f"Valid AKIA format: ****{key_id[-4:]}",
                    validator_name=self.name,
                )
            else:
                return ValidationResult(
                    state=ValidationState.INVALID,
                    reason="Invalid AWS Access Key ID format",
                    validator_name=self.name,
                )

        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"Validation error: {str(e)}",
                validator_name=self.name,
            )
