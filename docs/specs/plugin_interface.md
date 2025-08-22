# SecretScan360 — Detector Plugin Interface (v0.1)

## Goal
Make the scanner pluggable so new detectors can be dropped in without touching core logic.

## High-level design
- New package: `services/api/app/detectors/`
- Interface: each module exposes `class Detector:` with:
  - `name: str`
  - `version: str = "0.1.0"`
  - `kinds: list[str]` (e.g. ["AWS Access Key", "Private Key"])
  - `scan(path: str, content: str) -> list[dict]` producing items like:
    ```json
    {"path": "...", "kind": "AWS Access Key", "match": "AKIA...", "line": 42,
     "is_secret": true, "reason": "Heuristic or rule explanation", "detector":"regex"}
    ```
- Registry: `services/api/app/detectors/__init__.py` exposes:
  ```python
  def load_detectors() -> list:
      # import built-ins and return Detector instances
- Pipeline (in existing scan route):

After repo is materialized -> read files (size limit < 1 MB; skip binaries)

For each file, pass to all detectors, collect and return/save

First built-in plugin: RegexDetector

Module: services/api/app/detectors/regex_detector.py

Implement common secret patterns:

RSA/EC private key headers

AWS Access Key ID: AKIA[0-9A-Z]{16}

Generic API_KEY=<hex/uuidish>

Include light heuristics to avoid obvious test fixtures (e.g., ignore lines containing the word "EXAMPLE" unless overridden)

Config

Optional allowlist via env SS360_ALLOWLIST_PATTERNS (comma-separated regex); skip matches if any allowlist regex matches the line/match.
Tests

Add services/api/app/tests/test_detectors.py

Cases:

RegexDetector finds RSA key header.

Finds AWS key and marks is_secret=true unless "EXAMPLE" present.

Respects allowlist.

Wire tests into existing CI (pytest).
Back-compat

Keep /scan request/response stable.

Add field detector to each finding.
Done when

curl -s -X POST http://localhost:8000/scan -H 'content-type: application/json' -d '{"repo_url":"https://github.com/hashicorp/vault"}' returns findings with "detector":"regex".

Unit tests pass locally and in CI.
