# agents/dev/run_agent_impl.py
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent


REPO_ROOT = Path(__file__).resolve().parents[2]

# Optional: update this text dynamically in other steps.
# Keep it short here to avoid flake8 E501. Your task spec can be injected by the
# earlier "patch" step that overwrites the block between the BEGIN/END markers.
# === TASK_TEXT:BEGIN ===
TASK_TEXT = dedent(
    """
    Implement the next feature as described in docs/specs/*.md and commit to the feature branch.
    """
).strip()
# === TASK_TEXT:END ===


def run(cmd: list[str], cwd: Path | None = None) -> None:
    """Run a shell command and stream output; fail fast on non-zero exit."""
    print("$", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=str(cwd) if cwd else None)


def ensure_repo_root() -> None:
    """Exit if script is not executed from inside the repo."""
    try:
        run(["git", "rev-parse", "--is-inside-work-tree"])
    except subprocess.CalledProcessError:
        print("Error: not inside a git repository.", file=sys.stderr)
        sys.exit(1)


def ensure_git_identity() -> None:
    """Make sure git user is configured, default to Mohan's noreply if missing."""
    name = os.environ.get("GIT_USER_NAME", "Mohan Krishna Alavala")
    email = os.environ.get(
        "GIT_USER_EMAIL",
        "mohankrishnaalavala@users.noreply.github.com",
    )
    run(["git", "config", "user.name", name])
    run(["git", "config", "user.email", email])


def sync_main_branch() -> None:
    """
    Ensure main is up to date:
    - fetch
    - checkout main
    - try fast-forward; if diverged, do a no-ff merge of origin/main
    """
    run(["git", "fetch", "--all", "--prune"])
    run(["git", "checkout", "main"])
    try:
        run(["git", "pull", "--ff-only", "origin", "main"])
    except subprocess.CalledProcessError:
        # Diverged: fall back to merge to avoid interactive rebase
        print("Fast-forward failed; attempting non-ff merge with origin/main")
        run(
            [
                "git",
                "merge",
                "--no-ff",
                "origin/main",
                "-m",
                "chore: sync with origin/main",
            ]
        )


def checkout_feature_branch() -> str:
    """
    Create/switch to the feature branch specified by AGENT_BRANCH,
    defaulting to 'agent/feat-work-item'.
    """
    branch = os.environ.get("AGENT_BRANCH", "agent/feat-work-item")
    # Use -B to create or reset to current HEAD safely
    run(["git", "checkout", "-B", branch])
    return branch


def write_status_note(branch: str) -> None:
    """
    Optionally drop a lightweight agent status note. This is safe to commit
    and helps us confirm end-to-end commit flow.
    """
    note = REPO_ROOT / "agents" / "dev" / ".agent_status.txt"
    note.parent.mkdir(parents=True, exist_ok=True)
    content = (
        dedent(
            f"""
        Branch: {branch}
        Task (summary):
        {TASK_TEXT}
        """
        ).strip()
        + "\n"
    )
    note.write_text(content, encoding="utf-8")
    print(f"Wrote agent status note -> {note}")


def stage_commit_push(branch: str, message: str) -> None:
    """Stage all, commit (allow empty), and push branch upstream."""
    run(["git", "add", "-A"])
    try:
        run(["git", "commit", "--allow-empty", "-m", message])
    except subprocess.CalledProcessError:
        # If hooks fail, surface message and abort so caller can fix.
        print(
            "Commit failed (likely a pre-commit hook). Fix issues and re-run.",
            file=sys.stderr,
        )
        raise
    run(["git", "push", "-u", "origin", branch])


def main() -> None:
    ensure_repo_root()
    ensure_git_identity()
    sync_main_branch()
    branch = checkout_feature_branch()

    # Minimal no-op "touch" to ensure we always have at least one file updated
    write_status_note(branch)

    # Commit & push (hooks will run here)
    default_msg = os.environ.get(
        "AGENT_COMMIT_MSG",
        "chore(agent): checkpoint for current task",
    )
    stage_commit_push(branch, default_msg)

    print("\n✅ Agent runner completed successfully.")
    print(f"   Branch: {branch}")
    print("   You can now open a PR from this branch to main.")


if __name__ == "__main__":
    main()
