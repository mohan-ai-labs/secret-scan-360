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
Wire plugin registry into the scanning pipeline.

Goals:
1) Construct DetectorRegistry at agents service startup:
   - Load rules from services/agents/app/config/detectors.yaml if present,
     else use defaults from detectors.registry.DEFAULT_REGEX_RULES.
2) Update core scanner to iterate over registered detectors and merge findings.
3) Update POST /run (agents service) to accept repo_url and return findings produced by detectors.
4) Keep API response format identical to current /scan expectations (path, kind, match, line, is_secret, reason).
5) Add a unit test for registry wiring (at least one positive hit from RegexDetector).
6) Update README with a short 'Detector plugins' section and YAML override example.

Success checks:
- 'docker compose up -d' stays healthy.
- 'curl -s -X POST http://localhost:8000/scan -H content-type:application/json -d '{" + '"repo_url":"https://github.com/hashicorp/vault"' + "}' returns findings with kinds from RegexDetector (e.g., 'Private Key').
# === TASK_TEXT:END ===


"""
