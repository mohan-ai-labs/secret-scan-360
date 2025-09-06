#!/usr/bin/env python3
"""Test CLI bad config handling."""

import tempfile
import subprocess
import sys
from pathlib import Path


def run_cli_scan(root_path, raw_mode=False, config_path=None):
    """Run ss360 scan command and return result."""
    cmd = [
        sys.executable, "-c",
        """
import sys
sys.path.insert(0, '/home/runner/work/secret-scan-360/secret-scan-360/src')
from ss360.cli import main
try:
    exit_code = main(sys.argv[1:])
    sys.exit(exit_code)
except SystemExit:
    raise
""",
        "scan", str(root_path)
    ]
    
    if raw_mode:
        cmd.append("--raw")
    
    if config_path:
        cmd.extend(["--config", str(config_path)])
    
    return subprocess.run(cmd, capture_output=True, text=True, cwd=root_path)


def test_bad_config():
    """Test that bad config produces friendly SS360ConfigError with no traceback spam."""
    print("Testing bad config handling...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a file with a GitHub token
        secret_file = temp_path / "secrets.env"
        secret_file.write_text("GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890\n")
        
        # Create malformed config file
        bad_config_file = temp_path / "bad_config.yml"
        bad_config_file.write_text("""# Malformed YAML
include_globs:
  - "**/*"
exclude_globs: [
  - "**/.git/**"  # Missing closing bracket
  - "**/.venv/**"
""")
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "add", "secrets.env"], cwd=temp_path, capture_output=True)  # Don't add bad config
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_path, capture_output=True)
        
        # Test with explicitly provided bad config - should show friendly error
        print("  Testing with explicitly provided bad config...")
        result = run_cli_scan(temp_path, raw_mode=False, config_path=bad_config_file)
        
        print(f"  Return code: {result.returncode}")
        print(f"  Stdout: {result.stdout}")
        print(f"  Stderr: {result.stderr}")
        
        # Should fail with exit code 1
        assert result.returncode == 1, f"Expected exit code 1 for bad config, got {result.returncode}"
        
        # Should show friendly SS360ConfigError in stderr
        assert "CONFIG ERROR:" in result.stderr, f"Expected CONFIG ERROR in stderr, got: {result.stderr}"
        
        # Should include the absolute config path in the error
        expected_config_path = str(bad_config_file.resolve())
        assert expected_config_path in result.stderr, f"Expected config path {expected_config_path} in error: {result.stderr}"
        
        # Should NOT show Python traceback spam (no "Traceback" in stderr)
        assert "Traceback" not in result.stderr, f"Found unwanted traceback in error: {result.stderr}"
        
        print("✅ Bad config handling test passed")


def test_missing_explicit_config():
    """Test that missing explicitly provided config shows friendly error."""
    print("Testing missing explicit config...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a file with a GitHub token
        secret_file = temp_path / "secrets.env"
        secret_file.write_text("GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890\n")
        
        # Non-existent config file
        missing_config_file = temp_path / "missing_config.yml"
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_path, capture_output=True)
        
        # Test with missing config file - should show friendly error
        print("  Testing with missing config file...")
        result = run_cli_scan(temp_path, raw_mode=False, config_path=missing_config_file)
        
        print(f"  Return code: {result.returncode}")
        print(f"  Stdout: {result.stdout}")
        print(f"  Stderr: {result.stderr}")
        
        # Should fail with exit code 1
        assert result.returncode == 1, f"Expected exit code 1 for missing config, got {result.returncode}"
        
        # Should show friendly SS360ConfigError in stderr
        assert "CONFIG ERROR:" in result.stderr, f"Expected CONFIG ERROR in stderr, got: {result.stderr}"
        
        # Should mention file not found
        assert "not found" in result.stderr.lower(), f"Expected 'not found' in error: {result.stderr}"
        
        # Should include the absolute config path in the error
        expected_config_path = str(missing_config_file.resolve())
        assert expected_config_path in result.stderr, f"Expected config path {expected_config_path} in error: {result.stderr}"
        
        # Should NOT show Python traceback spam
        assert "Traceback" not in result.stderr, f"Found unwanted traceback in error: {result.stderr}"
        
        print("✅ Missing explicit config test passed")


if __name__ == "__main__":
    test_bad_config()
    test_missing_explicit_config()