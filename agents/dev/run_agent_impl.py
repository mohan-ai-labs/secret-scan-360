#!/usr/bin/env python3
"""
Agent Runner Implementation for SecretScan360
This script wires CrewAI agent(s) to implement and commit specific features
into a feature branch for development.
"""


import subprocess
from crewai import Agent, Task, Crew
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Git Helpers
# ---------------------------------------------------------------------------


def run(cmd):
    print(f"$ {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def ensure_branch(branch: str):
    run(["git", "fetch", "--all", "--prune"])
    try:
        run(["git", "checkout", branch])
    except subprocess.CalledProcessError:
        run(["git", "checkout", "-B", branch])
    run(["git", "pull", "--ff-only", "origin", branch])


# ---------------------------------------------------------------------------
# Agent & Task Setup
# ---------------------------------------------------------------------------

dev = Agent(
    role="Senior Python/FastAPI Engineer",
    goal="Implement API filters for /scans/latest endpoint with pagination and filtering",
    backstory=(
        "You are a backend engineer contributing to SecretScan360. "
        "You write secure, well-tested, PEP8-compliant code with FastAPI, SQL, and psycopg. "
        "You always use query placeholders for SQL (no string formatting). "
    ),
    verbose=True,
)

filters_spec = (
    "Add query params to GET /scans/latest:\n"
    "- limit (default 50, max 200), offset (default 0)\n"
    "- repo (substring filter on repo_url)\n"
    "- since (RFC3339 timestamp on started_at, inclusive)\n"
    "Update README with curl examples. Add minimal smoke test."
)

filters_task = Task(
    description=filters_spec,
    expected_output="Updated FastAPI route with filters, doc, and test committed to branch.",
    agent=dev,
)

crew = Crew(agents=[dev], tasks=[filters_task])

# ---------------------------------------------------------------------------
# Main Entrypoint
# ---------------------------------------------------------------------------


def main():
    branch = "agent/feat-api-filters"
    ensure_branch("main")
    run(["git", "checkout", "-B", branch])

    result = crew.kickoff()
    print("==== Agent run complete ====")
    print(result)

    run(["git", "add", "-A"])
    run(
        [
            "git",
            "commit",
            "--allow-empty",
            "-m",
            "feat(api): add filters for /scans/latest (agent)",
        ]
    )
    run(["git", "push", "origin", branch])


if __name__ == "__main__":
    main()


# Auto-injected task text for current feature
TASK_TEXT = """\
# === TASK_TEXT:BEGIN ===
Implement the Detector Plugin Interface and first RegexDetector.

Follow the spec at docs/specs/plugin_interface.md (copied below):

--- SPEC START ---
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

--- SPEC END ---

# Acceptance:
# - Code compiles, docker compose up -d works.
# - /scan returns findings with "detector":"regex".
# - Add unit tests in services/api/app/tests/test_detectors.py; ensure pytest passes.
# - Commit to branch: agent/feat-plugin-interface
# === TASK_TEXT:END ===
"""
