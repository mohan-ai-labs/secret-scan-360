import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

try:
    from services.agents.app.detectors.registry import DetectorRegistry
    from services.agents.app.core.scanner import Scanner
    SCANNER_AVAILABLE = True
except ImportError:
    SCANNER_AVAILABLE = False

import pytest

@pytest.mark.skipif(not SCANNER_AVAILABLE, reason="scanner modules not available")
def test_scanner_detects_aws_and_private_key(tmp_path: Path):
    # Create sample files
    f1 = tmp_path / "creds.txt"
    f1.write_text("token AKIA1234567890ABCDE end")
    f2 = tmp_path / "key.pem"
    f2.write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n"
    )

    # Load registry from seed YAML (repo path)
    cfg = Path("services/agents/app/config/detectors.yaml")
    assert cfg.exists(), "detectors.yaml not found"

    registry = DetectorRegistry.load_from_yaml(str(cfg))
    scanner = Scanner(registry=registry)

    findings = scanner.scan_paths([tmp_path])
    kinds = {f["kind"] for f in findings}
    assert "AWS Access Key" in kinds
    assert "Private Key" in kinds
    # minimal check that we captured some match text
    assert any("AKIA" in f["match"] for f in findings if f["kind"] == "AWS Access Key")
