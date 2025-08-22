# SecretScan360 Plugin Interface Specification

**Version:** 0.1.0  
**Scope:** Define a stable, extensible detector plugin interface for SecretScan360 so new detection
capabilities can be added without modifying core scanning logic.

---

## 1. Goals

- Decouple *what* to detect from *how* the core scans repositories.
- Allow multiple detectors to run in a pipeline and contribute findings.
- Keep the interface small, explicit, and easy to test.
- Support pure-Python detectors (no heavy binary deps required).
- Deterministic, side-effect free execution by default.

Non-goals (v0.1):
- Cross-repo correlation, provenance, or ML classifiers.
- Distributed execution; each scan assumes a local checkout/working directory.

---

## 2. Core Concepts & Terms

- **Detector**: A class that inspects source text and emits `Finding` objects when a secret (or likely secret) is found.
- **Registry**: A central list of available detectors. The scanner asks the registry for enabled detectors and runs them.
- **Finding**: A structured result representing a potential secret. Findings are aggregated and returned/stored.

---

## 3. Public Interfaces

### 3.1 `Finding` (dataclass)

```python
from dataclasses import dataclass
from typing import Optional, Dict

@dataclass(frozen=True)
class Finding:
    path: str                  # repo-relative file path
    kind: str                  # e.g. "Private Key", "AWS Access Key", "Generic API Key"
    match: str                 # the snippet that triggered detection (trimmed/safe)
    line: int                  # 1-based line number where match begins
    is_secret: bool            # final judgment by detector (True/False)
    reason: Optional[str] = None  # short explanation / heuristic
    meta: Optional[Dict[str, str]] = None  # detector-specific fields (optional)
```

> **Security note:** `match` should be **redacted** if it is sensitive. Leave only a short canonical snippet (e.g., first/last 4 chars).

### 3.2 `Detector` (abstract base)

```python
from abc import ABC, abstractmethod
from typing import Iterable

class Detector(ABC):
    """Base class for all detectors."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique detector name (e.g., 'regex', 'aws_keys')."""

    @abstractmethod
    def detect(self, path: str, text: str) -> Iterable[Finding]:
        """Inspect the given text content and yield zero or more findings."""
```

Rules:
- Detectors must be **pure functions** of `(path, text)`.
- No network, file, or DB access from detectors (the scanner coordinates I/O).
- Detectors should be fast; prefer compiled regex, minimal allocations.
- Detectors should avoid catastrophic regex backtracking; keep patterns safe.

### 3.3 `Registry`

```python
class DetectorRegistry:
    def __init__(self) -> None:
        self._detectors = []  # list[Detector]

    def register(self, detector: Detector) -> None:
        # Uniqueness by name
        if any(d.name == detector.name for d in self._detectors):
            raise ValueError(f"Duplicate detector: {detector.name}")
        self._detectors.append(detector)

    def all(self) -> list:
        return list(self._detectors)
```

The core scanner will hold a single `DetectorRegistry` instance and register built-ins during service startup.

---

## 4. Default Detectors (v0.1)

### 4.1 `RegexDetector`

Purpose: Provide a configurable regex-based detector that can cover common patterns quickly.

Config schema (YAML or Python dict):
```yaml
regex_detector:
  enabled: true
  rules:
    - name: "Private Key (RSA)"
      kind: "Private Key"
      pattern: "-----BEGIN RSA PRIVATE KEY-----"
      redact: true
    - name: "Private Key (EC)"
      kind: "Private Key"
      pattern: "-----BEGIN EC PRIVATE KEY-----"
      redact: true
    - name: "AWS Access Key"
      kind: "AWS Access Key"
      pattern: "\b(AKI[0-9A-Z]{17})\b"
      redact: true
    - name: "Generic API Key"
      kind: "Generic API Key"
      pattern: "\b(?i)(api_?key|token|secret)[:=]\s*([A-Za-z0-9_\-]{16,})\b"
      redact: true
```

Implementation outline:
```python
import re
from typing import Iterable, List

class RegexDetector(Detector):
    def __init__(self, rules: List[dict]) -> None:
        self._rules = []
        for r in rules:
            self._rules.append({
                "name": r["name"],
                "kind": r["kind"],
                "pattern": re.compile(r["pattern"]),
                "redact": bool(r.get("redact", True)),
            })

    @property
    def name(self) -> str:
        return "regex"

    def detect(self, path: str, text: str) -> Iterable[Finding]:
        for rule in self._rules:
            for m in rule["pattern"].finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                raw = m.group(0)
                shown = (raw[:4] + "…" + raw[-4:]) if rule["redact"] and len(raw) > 12 else raw
                yield Finding(
                    path=path,
                    kind=rule["kind"],
                    match=shown,
                    line=line,
                    is_secret=True,
                    reason=f"Matched rule: {rule['name']}",
                )
```

### 4.2 Future built-ins (stubs)
- `AwsKeyDetector` — stricter checksum heuristics for AKIA credentials.
- `Pkcs8KeyDetector` — PEM-format private key detection with structure checks.
- `GithubTokenDetector` — GH token prefixes/patterns with checksum.

---

## 5. Scanner ↔ Registry Integration

The scanner should:
1. Read repository files (respect `.gitignore` and size limits).
2. For each text file, pass `(path, text)` to every enabled detector in the registry.
3. Collect and deduplicate identical findings (same `path`, `line`, `kind`, `match`).
4. Return aggregated findings and optionally persist to Postgres.

Pseudo-code:

```python
def scan_repo(repo_root: Path, registry: DetectorRegistry) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_text_files(repo_root):
        text = path.read_text(errors="ignore")
        for det in registry.all():
            findings.extend(det.detect(str(path.relative_to(repo_root)), text))
    return dedupe(findings)
```

---

## 6. Service Wiring (FastAPI)

- On service startup:
  - Build a `DetectorRegistry`.
  - Load YAML config from `services/agents/app/config/detectors.yaml` (optional).
  - Register `RegexDetector` with rules (default rules if no config present).

- `/scan` endpoint:
  - Clones/downloads the repo into a temp dir (already exists).
  - Constructs registry → runs `scan_repo` → returns findings.
  - If `DB_ENABLED`, persists `scan` + `findings` within a transaction.

---

## 7. Configuration & Defaults

- File: `services/agents/app/config/detectors.yaml` (mounted/optional).
- Environment variables:
  - `DETECTORS_ENABLED`: comma-separated names to enable (default: `regex`).
  - `REGEX_RULES_PATH`: optional path to rules file to override built-ins.
- Safe defaults always include RSA/EC/AWS patterns above.

---

## 8. Testing Strategy

Unit tests:
- `tests/detectors/test_regex_detector.py`
  - Rule compiles, single & multiple matches returned.
  - Line numbers correct.
  - Redaction behavior correct.

Integration tests:
- `tests/integration/test_scan_pipeline.py`
  - Create temp repo with known secrets.
  - `scan_repo` finds expected findings.
  - `/scan` returns aggregated results; DB rows created when enabled.

---

## 9. Performance & Limits

- Max file size scanned: 512 KB (configurable).
- Max matches per file per rule: 100 (configurable) to avoid pathological inputs.
- Regex pre-compilation required; avoid nested catastrophic patterns.

---

## 10. Security Considerations

- Never log full secrets. Apply redaction before logging/returning.
- Respect `.gitignore` and ignore common binary/textually-ambiguous files.
- Avoid evaluating dynamic code or running shell in detectors.

---

## 11. Migration Notes (v0.1 → future)

- The `Detector` interface is minimal and can be extended with optional hooks:
  - `pre_repo(repo_root: Path)`, `post_repo(repo_root: Path, findings: list[Finding])`
- Consider a plugin discovery mechanism via entry points (setuptools) in v0.2.

---

## 12. Example: Wiring in `registry.py`

```python
from .base import Detector, DetectorRegistry, Finding
from .regex_detector import RegexDetector
import yaml

def build_registry(config_path: str | None = None) -> DetectorRegistry:
    reg = DetectorRegistry()

    rules = [
        {"name": "Private Key (RSA)", "kind": "Private Key", "pattern": "-----BEGIN RSA PRIVATE KEY-----", "redact": True},
        {"name": "Private Key (EC)", "kind": "Private Key", "pattern": "-----BEGIN EC PRIVATE KEY-----", "redact": True},
        {"name": "AWS Access Key", "kind": "AWS Access Key", "pattern": r"\b(AKI[0-9A-Z]{17})\b", "redact": True},
        {"name": "Generic API Key", "kind": "Generic API Key", "pattern": r"\b(?i)(api_?key|token|secret)[:=]\s*([A-Za-z0-9_\-]{16,})\b", "redact": True},
    ]

    if config_path:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f) or {}
            rules = (cfg or {}).get("regex_detector", {}).get("rules", rules)

    reg.register(RegexDetector(rules))
    return reg
```

---

## 13. Deliverables for This Feature

- `services/agents/app/detectors/base.py` — `Detector`, `Finding`
- `services/agents/app/detectors/regex_detector.py` — implementation
- `services/agents/app/detectors/registry.py` — `build_registry()` wiring
- `services/agents/app/config/detectors.yaml` — (optional) default config
- Tests:
  - `tests/detectors/test_regex_detector.py`
  - `tests/integration/test_scan_pipeline.py`
- Docs:
  - `docs/specs/plugin_interface.md` (this file)

---

## 14. Acceptance Criteria

- `/scan` still returns findings for the Vault repo.
- Removing a rule from config removes corresponding findings.
- Adding a new rule yields new findings without code changes.
- Unit + integration tests pass locally and in CI.

