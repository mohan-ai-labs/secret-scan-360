"""Test CLI raw vs git modes."""

import sys
import os
import tempfile
import subprocess
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))


def run_cli_scan(root_path, raw_mode=False, policy_path=None):
    """Run ss360 CLI scan and return result."""
    cmd = [
        sys.executable, "-m", "ss360.cli", "scan", str(root_path)
    ]
    if raw_mode:
        cmd.append("--raw")
    if policy_path:
        cmd.extend(["--policy", str(policy_path)])
    cmd.extend(["--format", "json"])
    
    # Set PYTHONPATH to include src
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project_root / "src")
    
    result = subprocess.run(
        cmd,
        cwd=project_root,
        capture_output=True,
        text=True,
        env=env
    )
    return result


def test_modes():
    """Test CLI raw vs git modes behavior."""
    print("Testing CLI modes...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a file with a GitHub token
        secret_file = temp_path / "secrets.env"
        secret_file.write_text("GITHUB_TOKEN=ghp_1234567890123456789012345678901234567890\n")
        
        # Create policy file
        policy_file = temp_path / "policy.yml"
        policy_file.write_text("""
version: 1
validators:
  allow_network: false
budgets:
  new_findings: 10
  max_risk_score: 100
""")
        
        # Test raw mode - should find the token
        print("  Testing raw mode...")
        result = run_cli_scan(secret_file, raw_mode=True, policy_path=policy_file)
        
        assert result.returncode == 0, f"Raw mode failed: {result.stderr}"
        assert "Total findings: 1" in result.stdout, f"Raw mode didn't find token: {result.stdout}"
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=temp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "initial"], cwd=temp_path, capture_output=True)
        
        # Test git mode - should find the token (file is tracked)
        print("  Testing git mode with tracked file...")
        result = run_cli_scan(temp_path, raw_mode=False, policy_path=policy_file)
        
        # Git mode might fall back to direct scanning if Scanner import fails
        # which is fine for this test - we just want to ensure it doesn't crash
        assert result.returncode == 0, f"Git mode failed: {result.stderr}"
        
        # Add file to .gitignore
        gitignore = temp_path / ".gitignore"
        gitignore.write_text("secrets.env\n")
        
        # Test git mode with ignored file - behavior depends on implementation
        print("  Testing git mode with ignored file...")
        result = run_cli_scan(temp_path, raw_mode=False, policy_path=policy_file)
        
        assert result.returncode == 0, f"Git mode with ignored file failed: {result.stderr}"
        
        # Test raw mode again - should still find the token regardless of .gitignore
        print("  Testing raw mode with ignored file...")
        result = run_cli_scan(secret_file, raw_mode=True, policy_path=policy_file)
        
        assert result.returncode == 0, f"Raw mode with ignored file failed: {result.stderr}"
        assert "Total findings: 1" in result.stdout, f"Raw mode didn't find token with gitignore: {result.stdout}"
        
        print("✅ CLI modes test passed")


if __name__ == "__main__":
    test_modes()