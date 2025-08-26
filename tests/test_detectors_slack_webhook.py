# Auto-generated smoke test for slack_webhook


def test_detector_import():
    import importlib
    import detectors.slack_webhook as m
    assert hasattr(m, "detect")
