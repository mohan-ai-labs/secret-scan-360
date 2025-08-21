# Secret Scan 360 (SS360) – PoC

- Infra: Hetzner CPX21, Ubuntu, Docker Compose
- Services: FastAPI API, Agents (Uvicorn), Postgres
- LLM: Agents call OpenAI directly via OPENAI_API_KEY
- Endpoints: /health, POST /scan, GET /scans/latest, GET /scans/{id}
- Persistence: scans + findings tables in Postgres
- Goal (next): GitHub PR Action to run scans on PRs and comment findings
