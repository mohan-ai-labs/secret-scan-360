from services.agents.app.detectors.regex_detector import RegexDetector


def test_regex_detector_basic():
    rules = [
        {
            "name": "AWS",
            "kind": "AWS Access Key",
            "pattern": r"\b(AKI[0-9A-Z]{17})\b",
            "redact": True,
        }
    ]
    det = RegexDetector(rules)
    text = "creds: AKIA1234567890ABCDE1 other text"
    out = list(det.detect("foo.txt", text))
    assert out, "Expected a match"
    assert out[0].kind == "AWS Access Key"
    assert out[0].path == "foo.txt"
