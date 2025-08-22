import uvicorn, os, json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .core.git_ops import shallow_clone, cleanup
from .core.scanner import scan_tree

app = FastAPI(title="ss360-agents")


class RunInput(BaseModel):
    repo_url: str


@app.post("/run")
def run_scan(inp: RunInput):
    repo = inp.repo_url.strip()
    if not repo:
        raise HTTPException(status_code=400, detail="repo_url required")
    workdir = None
    try:
        workdir = shallow_clone(repo)
        result = scan_tree(workdir)
        result["repo"] = repo
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if workdir:
            cleanup(workdir)


@app.get("/health")
def health():
    return {"ok": True, "service": "ss360-agents"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
