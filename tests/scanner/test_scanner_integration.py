import yaml
from pathlib import Path

# Import the registry + regex detector from the codebase
from services.agents.app.detectors.registry import DetectorRegistry
from services.agents.app.detectors.regex_detector import RegexDetector


def load_registry():
    cfg_path = Path("services/agents/app/config/detectors.yaml")
    cfg = yaml.safe_load(cfg_path.read_text())
    # Minimal factory: today we only wire RegexDetector via config
    registry = DetectorRegistry()
    # Expect structure like:
    # detectors:
    #   - type: regex
    #     name: AWS Access Key
    #     kind: AWS Access Key
    #     pattern: "\\b(AKI[0-9A-Z]{17})\\b"
    #     redact: true
    for det in cfg.get("detectors", []):
        if det.get("type") == "regex":
            registry.register(
                RegexDetector(
                    [
                        {
                            "name": det.get("name"),
                            "kind": det.get("kind"),
                            "pattern": det.get("pattern"),
                            "redact": bool(det.get("redact", True)),
                        }
                    ]
                )
            )
    return registry


def test_registry_finds_aws_key_from_config():
    registry = load_registry()
    # Known-like sample text
    text = "creds: AKIA1234567890ABCDEF something else"
    results = []
    for detector in registry.detectors():
        results.extend(list(detector.detect("sample.txt", text)))

    # We expect at least one match with kind mentioning AWS Access Key
    assert results, "Expected at least one finding from registry"
    kinds = {r.kind for r in results}
    assert any("AWS" in k or "Access Key" in k for k in kinds)
