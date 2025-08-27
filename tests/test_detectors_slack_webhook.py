def test_detector_import():
    import importlib
    m = importlib.import_module("detectors.slack_webhook")
    assert hasattr(m, "detect")
