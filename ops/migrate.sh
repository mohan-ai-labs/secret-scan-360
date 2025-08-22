#!/usr/bin/env bash
set -euo pipefail
echo "[migrate] Applying sql_init.sql to current DB..."
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /dev/stdin < sql_init.sql
echo "[migrate] Done."
