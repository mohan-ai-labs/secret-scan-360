#!/usr/bin/env python3
"""Test CLI git mode without config file."""

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


def test_git_mode_no_config():
    """Test git mode with no config file - should use defaults and find secrets."""
    print("Testing git mode without config...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a file with a GitHub token
        secret_file = temp_path / "secrets.env"
        secret_file.write_text("GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890\n")
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_path, capture_output=True)
        
        # Test git mode without config - should work and find the token
        print("  Testing git mode without config file...")
        result = run_cli_scan(temp_path, raw_mode=False)
        
        print(f"  Return code: {result.returncode}")
        print(f"  Stdout: {result.stdout}")
        print(f"  Stderr: {result.stderr}")
        
        # Should succeed (not crash)
        assert result.returncode == 0, f"Git mode without config failed: {result.stderr}"
        
        # Should find at least one secret 
        assert "Total findings: " in result.stdout
        # Extract the number from "Total findings: X"
        import re
        match = re.search(r"Total findings: (\d+)", result.stdout)
        if match:
            findings_count = int(match.group(1))
            assert findings_count >= 1, f"Expected ≥1 finding, got {findings_count}"
        
        # Should show it's using default scanner config
        assert "Using default scanner config" in result.stdout or "default" in result.stdout.lower()
        
        print("✅ Git mode without config test passed")


if __name__ == "__main__":
    test_git_mode_no_config()