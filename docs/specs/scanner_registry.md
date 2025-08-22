# Scanner ↔ Registry Integration (Spec)

Goal: The scanner service (services/agents/app/core/scanner.py) must use the DetectorRegistry
to run all active detectors over repo content and return consolidated findings.

## Requirements
1) Registry
   - Load rules/config from YAML (services/agents/app/config/detectors.yaml).
   - Initialize all detectors (e.g., RegexDetector) marked enabled: true.

2) Scanner
   - For each scanned file (path + text), call registry.detect(path, text).
   - Collect results into a list of dicts with keys:
     - path, kind, match, line (int), is_secret (bool), reason (short string)
   - Return consolidated list (no duplicates; keep first occurrence per (path, kind, match)).

3) API integration
   - /scan uses the scanner pipeline; API already returns findings (keep format consistent).

4) Tests
   - Unit tests proving:
     - Registry loads enabled detectors.
     - Scanner returns findings for simple text containing e.g. AKIA… or “BEGIN RSA PRIVATE KEY”.
     - De-duplication works.
   - Place under tests/scanner/test_scanner_pipeline.py.

5) Perf/Resilience
   - Gracefully skip unreadable/binary files; continue scanning.
   - Limit per-file matches to a reasonable default (e.g., 100) to avoid blowups.

## Acceptance
- `pytest -q tests/scanner/test_scanner_pipeline.py` passes
- `curl -s -X POST http://localhost:8000/scan -H 'content-type: application/json' -d '{"repo_url":"https://github.com/hashicorp/vault"}'` returns JSON with findings.
