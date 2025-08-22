import os, time, requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import psycopg
from psycopg_pool import ConnectionPool

APP_NAME = "ss360-api"
AGENTS_URL = os.getenv("AGENTS_URL", "http://agents:8080")
DATABASE_URL = os.getenv("DATABASE_URL")
app = FastAPI(title=APP_NAME)

# DB pool (psycopg3)
pool = ConnectionPool(
    DATABASE_URL, min_size=1, max_size=4, kwargs={"connect_timeout": 5}
)


class ScanInput(BaseModel):
    repo_url: str


def persist_scan(repo_url: str, result: dict, started: float, finished: float) -> int:
    findings = result.get("findings", [])
    true_hits = sum(1 for f in findings if f.get("is_secret"))
    duration_ms = int((finished - started) * 1000)
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scans (repo_url, started_at, finished_at, duration_ms, total_findings, true_hits)
            VALUES (%s, now(), now(), %s, %s, %s)
            RETURNING id
            """,
            (repo_url, duration_ms, len(findings), true_hits),
        )
        scan_id = cur.fetchone()[0]
        if findings:
            rows = [
                (
                    scan_id,
                    f.get("path", ""),
                    f.get("kind", ""),
                    f.get("match", ""),
                    bool(f.get("is_secret", False)),
                    f.get("reason", ""),
                )
                for f in findings
            ]
            cur.executemany(
                """
                INSERT INTO findings (scan_id, path, kind, match, is_secret, reason)
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                rows,
            )
        conn.commit()
        return scan_id


@app.get("/health")
def health():
    # quick DB check
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            _ = cur.fetchone()
        db_ok = True
    except Exception:
        db_ok = False
    return {"ok": True, "service": APP_NAME, "db": db_ok}


@app.post("/scan")
def scan(input: ScanInput):
    t0 = time.time()
    try:
        r = requests.post(
            f"{AGENTS_URL}/run", json={"repo_url": input.repo_url}, timeout=1800
        )
        r.raise_for_status()
        result = r.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"agents_error: {e}")
    t1 = time.time()
    try:
        scan_id = persist_scan(input.repo_url, result, t0, t1)
        result["scan_id"] = scan_id
        return result
    except Exception as e:
        # If DB insert fails, still return the findings
        return {"warning": f"db_error: {e}", **result}


# Minimal read APIs


@app.get("/scans/latest")
def latest_scans(limit: int = 10):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, repo_url, started_at, finished_at, duration_ms, total_findings, true_hits
            FROM scans ORDER BY id DESC LIMIT %s
        """,
            (limit,),
        )
        rows = cur.fetchall()
        return {
            "scans": [
                {
                    "id": r[0],
                    "repo_url": r[1],
                    "started_at": r[2],
                    "finished_at": r[3],
                    "duration_ms": r[4],
                    "total_findings": r[5],
                    "true_hits": r[6],
                }
                for r in rows
            ]
        }


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, repo_url, started_at, finished_at, duration_ms, total_findings, true_hits FROM scans WHERE id=%s",
            (scan_id,),
        )
        s = cur.fetchone()
        if not s:
            raise HTTPException(status_code=404, detail="scan not found")
        cur.execute(
            "SELECT path, kind, match, is_secret, reason FROM findings WHERE scan_id=%s ORDER BY id",
            (scan_id,),
        )
        f = cur.fetchall()
        return {
            "scan": {
                "id": s[0],
                "repo_url": s[1],
                "started_at": s[2],
                "finished_at": s[3],
                "duration_ms": s[4],
                "total_findings": s[5],
                "true_hits": s[6],
            },
            "findings": [
                {
                    "path": x[0],
                    "kind": x[1],
                    "match": x[2],
                    "is_secret": x[3],
                    "reason": x[4],
                }
                for x in f
            ],
        }
