#!/usr/bin/env python3 
import json, os, sys, urllib.request

def main():
    webhook = os.getenv("WEBHOOK", "")
    token   = os.getenv("TOKEN", "")

    # If not configured (e.g., forks), exit cleanly.
    if not webhook:
        print("WEBHOOK not set; skipping notify.", file=sys.stderr)
        return

    payload = {
        "event":    "gha.status",
        "repo":     os.getenv("GITHUB_REPOSITORY", ""),
        "status":   os.getenv("JOB_STATUS", ""),            # success | failure | cancelled
        "job":      os.getenv("GITHUB_JOB", ""),
        "job_id":   f"gha-{os.getenv('GITHUB_RUN_ID','')}",
        "branch":   os.getenv("GITHUB_REF_NAME", ""),
        "pr_number":os.getenv("PR_NUMBER", ""),
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Token": token or "",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8", "ignore")
            print(f"Hub HTTP: {resp.getcode()}")
            print(f"Hub response: {body}")
    except Exception as e:
        print(f"Hub notify failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
