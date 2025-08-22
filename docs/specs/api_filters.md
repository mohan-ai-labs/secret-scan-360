# API Filters & Pagination – Output

```python
from fastapi import FastAPI, Query, HTTPException
from typing import List, Optional
from pydantic import BaseModel
import asyncpg
import uvicorn

app = FastAPI()

# Database connection configuration
DATABASE_URL = "postgresql://user:password@localhost/dbname"

class Scan(BaseModel):
    id: int
    repo_url: str
    started_at: str

async def get_db_connection():
    return await asyncpg.connect(DATABASE_URL)

@app.get("/scans/latest", response_model=List[Scan])
async def get_latest_scans(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    repo: Optional[str] = None,
    since: Optional[str] = None
):
    conditions = []
    params = []

    if repo:
        conditions.append("repo_url ILIKE %s")
        params.append(f"%{repo}%")  # Substring search
    if since:
        conditions.append("started_at >= %s")
        params.append(since)

    where_clause = " AND ".join(conditions) if conditions else "TRUE"
    query = f"""
        SELECT id, repo_url, started_at
        FROM scans
        WHERE {where_clause}
        ORDER BY started_at DESC
        LIMIT $1 OFFSET $2
    """
    params.insert(0, limit)  # Insert limit at the start
    params.insert(1, offset)  # Insert offset at the second position

    async with get_db_connection() as connection:
        scans = await connection.fetch(query, *params)

    return [Scan(**scan) for scan in scans]


# Create necessary indexes (to be run once):
# CREATE INDEX idx_repo_url ON scans USING gin (to_tsvector('english', repo_url));
# CREATE INDEX idx_started_at ON scans (started_at);

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)

```

### README.md
```markdown
# Scans API

## Endpoints

### GET /scans/latest

Fetch the latest scans.

#### Query Parameters

- **limit**: (default: `50`, max: `200`) The number of results to return.
- **offset**: (default: `0`) The number of results to skip.
- **repo**: (optional) Substring filter on `repo_url`.
- **since**: (optional) RFC3339 timestamp to filter scans based on `started_at` (inclusive).

#### Example Requests

```bash
curl 'http://localhost:8000/scans/latest?limit=10&offset=0'
curl 'http://localhost:8000/scans/latest?limit=10&repo=example-repo'
curl 'http://localhost:8000/scans/latest?since=2023-10-01T00:00:00Z'
```
```

### Testing Instructions
To verify the integration of the API endpoint:

1. Start the server:
   ```bash
   python your_fastapi_app.py
   ```

2. Use curl or another HTTP client to test the endpoint:
   ```bash
   curl 'http://localhost:8000/scans/latest?limit=10&offset=0'
   ```

3. Ensure you have a test database with relevant data to validate different scenarios (filtering by `repo` and `since`).

### Minimal Smoke Test
You could include a minimal test in the main application file or a separate test module to verify the endpoint is live:
```python
import pytest
from fastapi.testclient import TestClient
from your_fastapi_app import app

client = TestClient(app)

def test_get_latest_scans():
    response = client.get("/scans/latest?limit=10&offset=0")
    assert response.status_code == 200
    assert "scans" in response.json()
```

This modifies the FastAPI route to incorporate limit, offset, repo, and since parameters according to your specifications. It ensures secure database access using parameter placeholders to prevent SQL injection, includes documentation for the new features, and provides a minimal smoke test to exercise this new functionality.
