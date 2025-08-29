def test_public_api_imports():
    from ss360.scanner import Scanner, DetectorRegistry

    assert Scanner and DetectorRegistry
