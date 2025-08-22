#!/usr/bin/env bash
set -euo pipefail

# Ensure .env exists
if [ ! -f ".env" ]; then
  cat > .env <<'ENV'
POSTGRES_USER=ss360
POSTGRES_PASSWORD=ss360
POSTGRES_DB=ss360
OPENAI_API_KEY=
LOG_LEVEL=info
ENV
  echo "[bootstrap] Wrote default .env"
fi

echo "[bootstrap] Building images..."
docker compose build

echo "[bootstrap] Starting services..."
docker compose up -d

echo "[bootstrap] Waiting for Postgres to be healthy..."
for i in {1..30}; do
  if docker compose ps | grep -q "postgres.*healthy"; then
    echo "[bootstrap] Postgres is healthy."
    break
  fi
  sleep 2
done

echo "[bootstrap] Applying DB schema..."
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /dev/stdin < sql_init.sql

echo "[bootstrap] Checking health..."
curl -s http://localhost:8000/health || true
echo
curl -s http://localhost:8080/health || true
echo
echo "[bootstrap] Done."
