#!/usr/bin/env python3
"""Test CLI git mode with config file."""

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


def test_git_mode_with_config():
    """Test git mode with .ss360.yml config file - should work and find secrets."""
    print("Testing git mode with config...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a file with a GitHub token
        secret_file = temp_path / "secrets.env"
        secret_file.write_text("GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890\n")
        
        # Create minimal .ss360.yml config
        config_file = temp_path / ".ss360.yml"
        config_file.write_text("""# Minimal SS360 config
include_globs:
  - "**/*"
exclude_globs:
  - "**/.git/**"
  - "**/.venv/**"
  - "**/node_modules/**"
min_match_length: 8
confidence_threshold: 0.0
disabled_detectors: []
""")
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_path, capture_output=True)
        
        # Test git mode with config - should work and find the token
        print("  Testing git mode with .ss360.yml config...")
        result = run_cli_scan(temp_path, raw_mode=False)
        
        print(f"  Return code: {result.returncode}")
        print(f"  Stdout: {result.stdout}")
        print(f"  Stderr: {result.stderr}")
        
        # Should succeed (not crash)
        assert result.returncode == 0, f"Git mode with config failed: {result.stderr}"
        
        # Should find at least one secret 
        assert "Total findings: " in result.stdout
        # Extract the number from "Total findings: X"
        import re
        match = re.search(r"Total findings: (\d+)", result.stdout)
        if match:
            findings_count = int(match.group(1))
            assert findings_count >= 1, f"Expected ≥1 finding, got {findings_count}"
        
        # Should show it loaded the config file
        expected_config_path = str(config_file)
        assert "Loaded config:" in result.stdout or expected_config_path in result.stdout
        
        print("✅ Git mode with config test passed")


if __name__ == "__main__":
    test_git_mode_with_config()