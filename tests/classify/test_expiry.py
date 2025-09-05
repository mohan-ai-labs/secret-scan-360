# SPDX-License-Identifier: MIT
"""
Tests for JWT and Azure SAS expiry detection.
"""
import json
import base64
from datetime import datetime, timedelta

import pytest

from src.ss360.classify.rules import (
    classify,
    _extract_jwt_expiry,
    _extract_azure_sas_expiry,
)


class TestExpiryDetection:
    """Test expiry detection for JWT and Azure SAS tokens."""

    def test_jwt_expired(self):
        """Test detection of expired JWT tokens."""
        # Create an expired JWT (expired 1 day ago)
        exp_time = datetime.utcnow() - timedelta(days=1)
        expired_jwt = self._create_test_jwt(exp_time)

        finding = {"match": expired_jwt, "path": "config.py", "kind": "JWT Token"}

        category, confidence, reasons = classify(finding)

        assert category == "expired"
        assert confidence > 0.9
        assert "offline:jwt_expired" in reasons

    def test_jwt_valid_future(self):
        """Test detection of valid JWT tokens with future expiry."""
        # Create a valid JWT (expires in 1 hour)
        exp_time = datetime.utcnow() + timedelta(hours=1)
        valid_jwt = self._create_test_jwt(exp_time)

        finding = {"match": valid_jwt, "path": "config.py", "kind": "JWT Token"}

        category, confidence, reasons = classify(finding)

        # Should not be classified as expired
        assert category != "expired"
        # May be classified as unknown or test based on other rules
        assert "offline:jwt_valid_future_exp" in reasons

    def test_azure_sas_expired(self):
        """Test detection of expired Azure SAS URLs."""
        # Create expired SAS URL (expired 1 day ago)
        exp_time = datetime.utcnow() - timedelta(days=1)
        exp_str = exp_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        sas_url = f"https://storageaccount.blob.core.windows.net/container/blob?se={exp_str}&sp=r&sv=2021-06-08&sr=b&sig=signature"

        finding = {"match": sas_url, "path": "azure_config.py", "kind": "Azure SAS"}

        category, confidence, reasons = classify(finding)

        assert category == "expired"
        assert confidence > 0.9
        assert "offline:azure_sas_expired" in reasons

    def test_azure_sas_valid_future(self):
        """Test detection of valid Azure SAS URLs with future expiry."""
        # Create valid SAS URL (expires in 1 hour)
        exp_time = datetime.utcnow() + timedelta(hours=1)
        exp_str = exp_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        sas_url = f"https://storageaccount.blob.core.windows.net/container/blob?se={exp_str}&sp=r&sv=2021-06-08&sr=b&sig=signature"

        finding = {"match": sas_url, "path": "azure_config.py", "kind": "Azure SAS"}

        category, confidence, reasons = classify(finding)

        # Should not be classified as expired
        assert category != "expired"
        assert "offline:azure_sas_valid_future_exp" in reasons

    def test_jwt_extract_expiry(self):
        """Test JWT expiry extraction function."""
        # Test valid JWT with expiry
        exp_time = datetime.utcnow() + timedelta(hours=1)
        jwt_token = self._create_test_jwt(exp_time)

        extracted_exp = _extract_jwt_expiry(jwt_token)
        assert extracted_exp is not None
        # Allow 1 second tolerance for timing
        assert abs((extracted_exp - exp_time).total_seconds()) < 1

    def test_azure_sas_extract_expiry(self):
        """Test Azure SAS expiry extraction function."""
        exp_time = datetime.utcnow() + timedelta(hours=1)
        exp_str = exp_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        sas_url = (
            f"https://storage.blob.core.windows.net/container/blob?se={exp_str}&sp=r"
        )

        extracted_exp = _extract_azure_sas_expiry(sas_url)
        assert extracted_exp is not None
        # Allow 1 second tolerance
        assert abs((extracted_exp - exp_time).total_seconds()) < 1

    def test_invalid_jwt_no_crash(self):
        """Test that invalid JWT doesn't crash the classifier."""
        invalid_jwt = "not.a.jwt"

        finding = {"match": invalid_jwt, "path": "config.py", "kind": "JWT Token"}

        # Should not crash
        category, confidence, reasons = classify(finding)
        assert category in ["actual", "expired", "test", "unknown"]

    def test_invalid_sas_no_crash(self):
        """Test that invalid SAS URL doesn't crash the classifier."""
        invalid_sas = "not-a-sas-url"

        finding = {"match": invalid_sas, "path": "config.py", "kind": "Azure SAS"}

        # Should not crash
        category, confidence, reasons = classify(finding)
        assert category in ["actual", "expired", "test", "unknown"]

    def _create_test_jwt(self, exp_time: datetime) -> str:
        """Create a test JWT token with specified expiry time."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "test",
            "exp": int(exp_time.timestamp()),
            "iat": int(datetime.utcnow().timestamp()),
        }

        # Encode header and payload
        header_encoded = (
            base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        )

        payload_encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )

        # Create fake signature (for testing, we don't need real signature)
        signature = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip("=")

        return f"{header_encoded}.{payload_encoded}.{signature}"
