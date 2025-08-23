# services/agents/app/server.py
from fastapi import FastAPI
from pydantic import BaseModel

from services.agents.app.core.scanner import Scanner

app = FastAPI()


class RunRequest(BaseModel):
    repo_path: str | None = None
    paths: list[str] | None = None  # alternatively allow direct paths


@app.get("/health")
def health():
    return {"ok": True, "service": "ss360-agents"}


@app.post("/run")
def run(req: RunRequest):
    # You probably have logic elsewhere to clone repo_url -> workspace path.
    roots = []
    if req.repo_path:
        roots.append(req.repo_path)
    if req.paths:
        roots.extend(req.paths)

    scanner = Scanner.from_config("services/agents/app/config/detectors.yaml")
    findings = scanner.scan_paths(roots or ["."])
    return {"ok": True, "findings": findings}
