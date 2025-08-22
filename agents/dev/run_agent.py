# agents/dev/run_agent.py
import os, subprocess, textwrap
from pathlib import Path
from dotenv import load_dotenv
from crewai import Agent, Task, Crew

REPO_ROOT = Path(__file__).resolve().parents[2]  # .../secret-scan-360
load_dotenv(REPO_ROOT / ".env")


def run(cmd, cwd=None):
    print(f"$ {cmd}")
    res = subprocess.run(
        cmd,
        cwd=cwd or REPO_ROOT,
        shell=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(res.stdout)
    if res.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}")
    return res.stdout


def ensure_git_config():
    # Keep commits under Mohan's name
    run('git config user.name "Mohan Krishna Alavala"')
    run('git config user.email "mohankrishnaalavala@users.noreply.github.com"')


def create_branch(branch):
    run("git fetch --all --prune")
    run("git checkout main")
    run("git pull --ff-only origin main")
    run(f"git checkout -B {branch}")


def commit_push(branch, message):
    run("git add -A")
    run(f'git commit --allow-empty -m "{message}"')
    run(f"git push -u origin {branch} --force-with-lease")


def write_file(relpath: str, content: str):
    path = REPO_ROOT / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[write] {relpath} ({len(content)} bytes)")


# --------------- LLM / Agent -----------------
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
if not OPENAI_API_KEY:
    raise SystemExit("OPENAI_API_KEY missing in .env")

dev = Agent(
    role="Senior Python/FastAPI Engineer",
    goal="Implement SS360 features in a plugin-friendly way with tests and docs.",
    backstory="Expert in static analysis, secure coding, SQL, and FastAPI.",
    verbose=True,
    allow_delegation=False,
    llm="gpt-4o-mini",  # uses OpenAI via your env
)

# --------------- Tasks -----------------
filters_spec = textwrap.dedent(
    """
Add query params to GET /scans/latest:
- limit (default 50, max 200), offset (default 0)
- repo (substring filter on repo_url)
- since (RFC3339 timestamp on started_at, inclusive)

Implement safely with psycopg placeholders (no string formatting).
Add helpful indexes if needed.
Update README with examples.
Add a minimal smoke-test (or docstring test) so CI can exercise it.

Success:
- `curl 'http://localhost:8000/scans/latest?limit=10&offset=0'` returns 200 JSON with an array 'scans'.
- repo & since filters narrow results.
"""
).strip()

filters_expected = textwrap.dedent(
    """
- Modified FastAPI route applying limit/offset/repo/since with validation and sane defaults (limit<=200).
- SQL uses parameter placeholders.
- README section with examples for new params.
- Minimal test/smoke instructions.
- Commands to run server+test are documented.
"""
).strip()

detectors_spec = textwrap.dedent(
    """
Add 3 detectors under services/agents/app/detectors/ with a central registry:
1) stripe_keys.py – detect: sk_live_, sk_test_, rk_live_, rk_test_
2) slack_tokens.py – detect: xoxb-, xoxp-, xoxa-, xoxr-, xoxs-
3) google_api_keys.py – detect: AIza[0-9A-Za-z-_]{35}

Each detector exposes:
- name: str
- patterns: list[compiled regex]
- detect(path: str, text: str) -> list[dict] with {path, kind, match, line, is_secret, reason}

Register all in detectors/registry.py so the scanning pipeline uses them.
Return findings with line and short reason.

Success: scanning a repo containing these patterns yields findings with proper `kind` and reason.
"""
).strip()

detectors_expected = textwrap.dedent(
    """
- New detector modules added; imported by a central registry.
- Regexes compiled once; safe patterns (no catastrophic backtracking).
- Findings include line number and reason.
- Basic test or fixture-based smoke instructions included.
"""
).strip()

filters_task = Task(
    description=filters_spec,
    expected_output=filters_expected,
    agent=dev,
)

detectors_task = Task(
    description=detectors_spec,
    expected_output=detectors_expected,
    agent=dev,
)


def main():
    ensure_git_config()

    # Branch 1: API filters/pagination
    create_branch("agent/feat-api-filters")
    crew1 = Crew(agents=[dev], tasks=[filters_task])
    out1 = crew1.kickoff()  # <-- no args in current CrewAI
    # Persist the agent output so we have a concrete diff to commit
    write_file(
        "docs/specs/api_filters.md", f"# API Filters & Pagination – Output\n\n{out1}\n"
    )
    commit_push(
        "agent/feat-api-filters", "spec(api): filters & pagination (agent output)"
    )

    # Branch 2: Detectors
    create_branch("agent/feat-detectors")
    crew2 = Crew(agents=[dev], tasks=[detectors_task])
    out2 = crew2.kickoff()  # <-- no args
    write_file("docs/specs/detectors.md", f"# Detectors – Output\n\n{out2}\n")
    commit_push("agent/feat-detectors", "spec(agents): detectors (agent output)")

    print("\nDone. Open PRs for both branches on GitHub.")


if __name__ == "__main__":
    main()
