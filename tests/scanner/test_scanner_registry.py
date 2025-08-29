from pathlib import Path

from services.agents.app.detectors.registry import DetectorRegistry
from services.agents.app.core.scanner import Scanner


def test_scanner_detects_aws_and_private_key(tmp_path: Path):
    # Create sample files
    f1 = tmp_path / "creds.txt"
    f1.write_text("token AKIA1234567890ABCDE end")
    f2 = tmp_path / "key.pem"
    f2.write_text("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")

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
