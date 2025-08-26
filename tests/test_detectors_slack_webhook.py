# Auto-generated smoke test for slack_webhook


def test_detector_import():
    import importlib
    importlib.import_module("detectors.slack_webhook")
    import detectors.slack_webhook as m
    assert hasattr(m, "detect")
