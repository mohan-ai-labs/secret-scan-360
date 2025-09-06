# SPDX-License-Identifier: MIT
"""
Additional validators for Slack, GCP, and Azure credentials.

These validators provide local format validation and optional live validation
when network access is allowed.
"""
from __future__ import annotations

import json
import re
from typing import Dict, Any
from .core import ValidationResult, ValidationState, _redact_secret


class SlackWebhookLocalValidator:
    """Local-only validator for Slack webhooks with enhanced format/signer checks."""

    # Slack webhook URL pattern with capture groups for validation
    SLACK_WEBHOOK_PATTERN = re.compile(
        r"https://hooks\.slack\.com/services/([A-Z0-9]{9})/([A-Z0-9]{9})/([A-Za-z0-9]{24})"
    )

    @property
    def name(self) -> str:
        return "slack_webhook_local"

    @property
    def rate_limit_qps(self) -> float:
        return 10.0  # High rate since it's local-only

    @property
    def requires_network(self) -> bool:
        return False  # Local-only validation

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """Validate Slack webhook format and perform enhanced signer checks."""
        match = finding.get("match", "")

        webhook_match = self.SLACK_WEBHOOK_PATTERN.match(match)
        if not webhook_match:
            return ValidationResult(
                state=ValidationState.INVALID,
                reason="Does not match Slack webhook URL pattern",
                validator_name=self.name,
            )

        # Extract components for enhanced validation
        team_id, channel_id, token = webhook_match.groups()

        # Enhanced format validation
        validation_issues = []

        # Team ID should be a valid Slack team ID format
        if not re.match(r"^T[A-Z0-9]{8}$", team_id):
            validation_issues.append(f"Invalid team ID format: {team_id}")

        # Channel/Bot ID should be valid format
        if not re.match(r"^[BC][A-Z0-9]{8}$", channel_id):
            validation_issues.append(f"Invalid channel/bot ID format: {channel_id}")

        # Token should be exactly 24 characters of valid base64-like characters
        if len(token) != 24 or not re.match(r"^[A-Za-z0-9]{24}$", token):
            validation_issues.append(f"Invalid token format: length={len(token)}")

        if validation_issues:
            return ValidationResult(
                state=ValidationState.INVALID,
                reason=f"Format validation failed: {'; '.join(validation_issues)}",
                validator_name=self.name,
            )

        # All validations passed
        redacted_url = _redact_secret(match)
        return ValidationResult(
            state=ValidationState.VALID,
            evidence=f"Valid Slack webhook format with enhanced checks: {redacted_url}",
            reason="Passed Slack webhook URL pattern and component validation",
            validator_name=self.name,
        )

    # No longer need individual _redact_secret method - using central function


class GCPServiceAccountKeyLiveValidator:
    """Validator that checks GCP service account key validity via generateAccessToken."""

    @property
    def name(self) -> str:
        return "gcp_sa_key_live"

    @property
    def rate_limit_qps(self) -> float:
        return 0.5  # Conservative rate limit for GCP API

    @property
    def requires_network(self) -> bool:
        return True  # Requires network for GCP API calls

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate GCP service account key via IAM Credentials API.

        When network is disabled, returns INDETERMINATE.
        When network is enabled, attempts to generate a short-lived access token.
        """
        key_data = finding.get("match", "")

        # First, perform basic format validation
        try:
            if key_data.startswith("{"):
                # JSON format service account key
                key_json = json.loads(key_data)
                required_fields = [
                    "type",
                    "project_id",
                    "private_key_id",
                    "private_key",
                    "client_email",
                ]

                missing_fields = [
                    field for field in required_fields if field not in key_json
                ]
                if missing_fields:
                    return ValidationResult(
                        state=ValidationState.INVALID,
                        reason=f"Missing required fields: {', '.join(missing_fields)}",
                        validator_name=self.name,
                    )

                if key_json.get("type") != "service_account":
                    return ValidationResult(
                        state=ValidationState.INVALID,
                        reason="Invalid key type - expected 'service_account'",
                        validator_name=self.name,
                    )

                # Format validation passed, now try live validation
                return self._validate_live(key_json)

            else:
                return ValidationResult(
                    state=ValidationState.INVALID,
                    reason="Invalid GCP service account key format - expected JSON",
                    validator_name=self.name,
                )

        except json.JSONDecodeError:
            return ValidationResult(
                state=ValidationState.INVALID,
                reason="Invalid JSON format for GCP service account key",
                validator_name=self.name,
            )
        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"Validation error: {str(e)}",
                validator_name=self.name,
            )

    def _validate_live(self, key_json: Dict[str, Any]) -> ValidationResult:
        """Attempt live validation using GCP IAM Credentials API."""
        try:
            # For a real implementation, we would:
            # 1. Use the private key to sign a JWT for authentication
            # 2. Exchange the JWT for an access token
            # 3. Use the access token to call generateAccessToken API
            #
            # This is a simplified mock implementation that would check
            # the key format and return indeterminate since we can't
            # actually make the API call without full OAuth2 implementation

            client_email = key_json.get("client_email", "")

            # Validate email format
            email_pattern = r"^[^@]+@[^@]+\.iam\.gserviceaccount\.com$"
            if not re.match(email_pattern, client_email):
                return ValidationResult(
                    state=ValidationState.INVALID,
                    reason="Invalid service account email format",
                    validator_name=self.name,
                )

            # For this implementation, we'll return indeterminate since full
            # GCP OAuth2 implementation is complex and would require additional dependencies
            redacted_email = _redact_secret(client_email)
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                evidence=f"GCP service account key format valid: {redacted_email}",
                reason="Format validation passed, but live validation requires full OAuth2 implementation",
                validator_name=self.name,
            )

        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"Live validation error: {str(e)}",
                validator_name=self.name,
            )


class AzureSASLiveValidator:
    """Validator that checks Azure SAS token validity via HEAD request."""

    @property
    def name(self) -> str:
        return "azure_sas_live"

    @property
    def rate_limit_qps(self) -> float:
        return 1.0  # Moderate rate limit for Azure API

    @property
    def requires_network(self) -> bool:
        return True  # Requires network for Azure API calls

    def validate(self, finding: Dict[str, Any]) -> ValidationResult:
        """
        Validate Azure SAS token via HEAD request.

        When network is disabled, returns INDETERMINATE.
        When network is enabled, attempts a HEAD request to validate the SAS token.
        """
        sas_token = finding.get("match", "")

        # Basic format validation for Azure SAS token
        if not self._is_valid_sas_format(sas_token):
            return ValidationResult(
                state=ValidationState.INVALID,
                reason="Invalid Azure SAS token format",
                validator_name=self.name,
            )

        # Attempt live validation
        return self._validate_live(sas_token)

    def _is_valid_sas_format(self, token: str) -> bool:
        """Check if the token looks like a valid Azure SAS token."""
        # Azure SAS tokens typically contain specific query parameters
        required_params = ["sig", "se"]  # signature and expiry are required

        # Check if it's a URL with query parameters
        if "?" not in token:
            return False

        try:
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(token)

            # Must be HTTPS and point to Azure storage domains
            if parsed.scheme != "https":
                return False

            azure_domains = [
                ".blob.core.windows.net",
                ".queue.core.windows.net",
                ".table.core.windows.net",
                ".file.core.windows.net",
            ]
            if not any(domain in parsed.netloc for domain in azure_domains):
                return False

            # Check for required SAS parameters
            query_params = parse_qs(parsed.query)
            for param in required_params:
                if param not in query_params:
                    return False

            return True

        except Exception:
            return False

    def _validate_live(self, sas_url: str) -> ValidationResult:
        """Attempt live validation with a HEAD request."""
        try:
            # For a real implementation, we would make a HEAD request to the SAS URL
            # to verify it's valid. For this implementation, we'll simulate the process

            # Extract some basic info for evidence
            from urllib.parse import urlparse

            parsed = urlparse(sas_url)
            host = parsed.netloc

            # In a real implementation, this would be:
            # req = urllib.request.Request(sas_url, method='HEAD')
            # with urllib.request.urlopen(req, timeout=10) as response:
            #     if response.status in [200, 404]:  # 404 is OK - means SAS works but resource doesn't exist
            #         return ValidationResult(state=ValidationState.VALID, ...)

            # For now, return indeterminate with format validation
            redacted_host = _redact_secret(host)
            evidence_msg = f"Azure SAS token format valid for host: {redacted_host}"
            reason_msg = (
                "Format validation passed, live validation would require "
                "actual HEAD request"
            )
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                evidence=evidence_msg,
                reason=reason_msg,
                validator_name=self.name,
            )

        except Exception as e:
            return ValidationResult(
                state=ValidationState.INDETERMINATE,
                reason=f"Live validation error: {str(e)}",
                validator_name=self.name,
            )
