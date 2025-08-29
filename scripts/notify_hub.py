# minimal hub notifier used by CI
import json, os, sys, urllib.request

WEBHOOK = os.getenv("AGENTS_WEBHOOK_URL", "")
TOKEN   = os.getenv("AGENTS_WEBHOOK_TOKEN", "")

def main():
    payload = {
        "event": "gha.status",
        "repo": os.getenv("GITHUB_REPOSITORY",""),
        "status": sys.argv[1] if len(sys.argv)>1 else "",
        "job":    os.getenv("GITHUB_JOB",""),
        "job_id": f"gha-{os.getenv('GITHUB_RUN_ID','')}",
        "branch": os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME",""),
        "pr_number": os.getenv("PR_NUMBER",""),
    }
    if not WEBHOOK:
        print("notify_hub: WEBHOOK not set; skipping")
        return
    req = urllib.request.Request(
        WEBHOOK,
        data=json.dumps(payload).encode(),
        headers={"Content-Type":"application/json","X-Agent-Token":TOKEN or ""},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            print("notify_hub:", resp.status, resp.read().decode())
    except Exception as e:
        print("notify_hub error:", e, file=sys.stderr)

if __name__ == "__main__":
    main()
