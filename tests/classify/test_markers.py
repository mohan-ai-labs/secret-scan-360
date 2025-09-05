# SPDX-License-Identifier: MIT
"""
Tests for test marker detection in classification.
"""
import pytest

from src.ss360.classify.rules import classify


class TestMarkerDetection:
    """Test detection of test/sample/demo markers."""

    def test_test_path_patterns(self):
        """Test classification based on test path patterns."""
        test_cases = [
            ("tests/config.py", "test", 0.9),
            ("test/secrets.py", "test", 0.9),
            ("fixtures/data.py", "test", 0.9),
            ("examples/demo.py", "test", 0.9),
            ("samples/auth.py", "test", 0.9),
            ("mocks/api.py", "test", 0.9),
            ("demos/setup.py", "test", 0.9),
            ("spec/helpers.py", "test", 0.9),
            ("__tests__/unit.py", "test", 0.9),
            ("src/run_tests.py", "test", 0.9),
            ("test_authentication.py", "test", 0.9),
            ("auth_test.py", "test", 0.9),
        ]
        
        for path, expected_category, min_confidence in test_cases:
            finding = {
                "match": "ghp_1234567890abcdef1234567890abcdef12345678",
                "path": path,
                "kind": "GitHub Token"
            }
            
            category, confidence, reasons = classify(finding)
            
            assert category == expected_category, f"Path {path} should be classified as {expected_category}"
            assert confidence >= min_confidence, f"Path {path} should have confidence >= {min_confidence}"
            assert any("path:" in reason for reason in reasons), f"Should have path-based reason for {path}"

    def test_filename_patterns(self):
        """Test classification based on filename patterns."""
        test_cases = [
            # Cases that should only match filename, not path patterns
            ("config/sample_env.py", "test", 0.8),  # filename: sample
            ("src/example_setup.py", "test", 0.8),  # filename: example  
            ("utils/dummy_data.py", "test", 0.8),   # filename: dummy
            ("helpers/fixture_loader.py", "test", 0.8),  # filename: fixture
            ("api/mock_client.py", "test", 0.8),    # filename: mock
            ("demo_runner.py", "test", 0.8),        # filename: demo
            ("lib/test_helper.py", "test", 0.8),    # filename: test (not path pattern)
        ]
        
        for path, expected_category, min_confidence in test_cases:
            finding = {
                "match": "AKIA1234567890ABCDEF",
                "path": path,
                "kind": "AWS Access Key"
            }
            
            category, confidence, reasons = classify(finding)
            
            assert category == expected_category, f"Filename in {path} should be classified as {expected_category}"
            assert confidence >= min_confidence, f"Filename in {path} should have confidence >= {min_confidence}"
            # Should have either filename-based or path-based reason
            has_filename_reason = any("filename:" in reason for reason in reasons)
            has_path_reason = any("path:" in reason for reason in reasons)
            assert has_filename_reason or has_path_reason, f"Should have filename or path-based reason for {path}"

    def test_value_content_markers(self):
        """Test classification based on value content markers."""
        test_cases = [
            ("TEST_API_KEY_123456", "test", 0.7),     # Explicit TEST marker
            ("EXAMPLE_SECRET_VALUE", "test", 0.7),    # Explicit EXAMPLE marker  
            ("DUMMY_PASSWORD_123", "test", 0.7),      # Explicit DUMMY marker
            ("SAMPLE_TOKEN_ABCDEF", "test", 0.7),     # Explicit SAMPLE marker
            ("MOCK_CREDENTIAL_XXX", "test", 0.7),     # Explicit MOCK marker
            ("FAKE_API_KEY_000000", "test", 0.7),     # Explicit FAKE marker
            ("PLACEHOLDER_SECRET", "test", 0.7),      # Explicit PLACEHOLDER marker
            ("XXX_REPLACE_ME_XXX", "test", 0.7),      # Explicit XXX marker
            ("000000000000000000", "test", 0.7),      # All zeros pattern
            ("000000", "test", 0.7),                  # Short obvious placeholder
            ("111111111111", "test", 0.7),            # Repeated digit pattern
        ]
        
        for match_value, expected_category, min_confidence in test_cases:
            finding = {
                "match": match_value,
                "path": "src/config.py",
                "kind": "API Key"
            }
            
            category, confidence, reasons = classify(finding)
            
            assert category == expected_category, f"Value {match_value} should be classified as {expected_category}"
            assert confidence >= min_confidence, f"Value {match_value} should have confidence >= {min_confidence}"
            assert any("marker:" in reason for reason in reasons), f"Should have marker-based reason for {match_value}"

    def test_production_paths_not_test(self):
        """Test that production-like paths are not classified as test."""
        production_paths = [
            "src/main.py",
            "production/config.py",
            "deploy/secrets.py",
            "config/prod.env",
            "app/auth.py",
            "lib/crypto.py",
        ]
        
        for path in production_paths:
            finding = {
                "match": "real_api_key_abcdef123456",
                "path": path,
                "kind": "API Key"
            }
            
            category, confidence, reasons = classify(finding)
            
            # Should not be classified as test based on path
            if category == "test":
                # If classified as test, it should be due to value content, not path
                assert not any("path:" in reason for reason in reasons), f"Production path {path} should not trigger path-based test classification"

    def test_combined_markers_high_confidence(self):
        """Test that multiple test markers increase confidence."""
        finding = {
            "match": "TEST_SECRET_123456",  # Value marker
            "path": "tests/sample_config.py",  # Path + filename markers
            "kind": "API Key"
        }
        
        category, confidence, reasons = classify(finding)
        
        assert category == "test"
        # Should get high confidence from path (0.9) rather than value marker (0.7)
        assert confidence >= 0.9
        # Should prioritize path-based classification
        assert any("path:" in reason for reason in reasons)

    def test_case_insensitive_matching(self):
        """Test that marker detection is case insensitive."""
        test_cases = [
            "test_value",
            "TEST_VALUE", 
            "Test_Value",
            "tEsT_vAlUe",
        ]
        
        for match_value in test_cases:
            finding = {
                "match": match_value,
                "path": "src/config.py",
                "kind": "API Key"
            }
            
            category, confidence, reasons = classify(finding)
            
            assert category == "test", f"Value {match_value} should be classified as test (case insensitive)"
            assert any("marker:" in reason for reason in reasons)

    def test_no_false_positives(self):
        """Test that normal values don't trigger test markers."""
        normal_values = [
            "ghp_1234567890abcdef1234567890abcdef12345678",  # Real-looking GitHub token
            "AKIA1234567890ABCDEF",  # Real-looking AWS key
            "sk_live_1234567890abcdef",  # Real-looking Stripe key
            "production_api_key_secure",  # Contains "production" 
        ]
        
        for match_value in normal_values:
            finding = {
                "match": match_value,
                "path": "src/config.py",  # Normal path
                "kind": "API Key"
            }
            
            category, confidence, reasons = classify(finding)
            
            # Should not be classified as test based on value content
            if category == "test":
                # Check that it's not due to content markers
                test_markers = [r for r in reasons if "marker:" in r]
                assert len(test_markers) == 0, f"Value {match_value} should not trigger test content markers"