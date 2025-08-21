import os, shutil, tempfile, re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from git import Repo
import requests
import json

app = FastAPI(title="ss360-agents")

# Simple patterns (we'll expand later)
SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
    (r'(?i)api[_-]?key[\'":= ]+([A-Za-z0-9_\-]{16,})', 'Generic API Key'),
    (r'ghp_[A-Za-z0-9]{36}', 'GitHub PAT'),
    (r'-----BEGIN (?:RSA|EC|DSA) PRIVATE KEY-----', 'Private Key'),
]

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("MODEL_NAME", "gpt-4o-mini")  # default

class RunInput(BaseModel):
    repo_url: str

def classify_with_llm(snippet: str, kind: str):
    """
    Calls OpenAI Chat Completions API directly.
    Returns (is_secret: bool, reason: str)
    """
    if not OPENAI_API_KEY:
        return False, "missing OPENAI_API_KEY"
    try:
        r = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            f"You are a security reviewer. "
                            f"Does this look like a REAL {kind}? "
                            f"Reply with compact JSON: "
                            f'{{"is_secret": true/false, "reason": "<short>"}}.\n\n'
                            f"Snippet:\n```{snippet[:1500]}```"
                        ),
                    }
                ],
                "temperature": 0.0,
                "max_tokens": 120,
            },
            timeout=60,
        )
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        # Extract JSON object from the response
        m = re.search(r"\{.*\}", content, re.S)
        data = json.loads(m.group(0)) if m else {}
        return bool(data.get("is_secret", False)), data.get("reason", "parsed")
    except Exception as e:
        return False, f"llm_error: {e}"

def list_text_files(root):
    for base, _, files in os.walk(root):
        for f in files:
            path = os.path.join(base, f)
            # skip >2MB and likely binaries
            try:
                if os.path.getsize(path) > 2_000_000:
                    continue
            except Exception:
                continue
            try:
                with open(path, "r", errors="ignore") as fh:
                    _ = fh.read(1)  # touch
                yield path
            except Exception:
                continue

@app.post("/run")
def run_scan(input: RunInput):
    tmpdir = tempfile.mkdtemp(prefix="scan-")
    results = []
    try:
        Repo.clone_from(input.repo_url, tmpdir, depth=1)
        for path in list_text_files(tmpdir):
            try:
                text = open(path, "r", errors="ignore").read()
            except Exception:
                continue
            for pat, kind in SECRET_PATTERNS:
                for m in re.finditer(pat, text):
                    snippet = text[max(0, m.start()-80): m.end()+80]
                    is_secret, reason = classify_with_llm(snippet, kind)
                    results.append({
                        "path": path.replace(tmpdir, ""),
                        "kind": kind,
                        "match": m.group(0) if isinstance(m.group(0), str) else "",
                        "is_secret": is_secret,
                        "reason": reason
                    })
        true_hits = [r for r in results if r["is_secret"]]
        return {"ok": True, "repo": input.repo_url, "findings": results, "true_hits": true_hits}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
