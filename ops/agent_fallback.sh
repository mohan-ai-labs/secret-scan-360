#!/usr/bin/env bash
set -euo pipefail
git fetch --all --prune
git checkout main
git pull --ff-only origin main

branch1="agent/spec-api-filters"
git checkout -B "$branch1"
mkdir -p docs/specs
cat > docs/specs/api_filters.md <<'MD'
# API Filters & Pagination – Spec
[Same acceptance criteria as in run_agent.py]
MD
git add -A && git commit -m "spec(api): filters & pagination" || true
git push -u origin "$branch1" --force-with-lease

branch2="agent/spec-detectors"
git checkout -B "$branch2"
mkdir -p docs/specs
cat > docs/specs/detectors.md <<'MD'
# Detectors – Spec
[Stripe/Slack/Google keys; registry; tests; reasons; patterns]
MD
git add -A && git commit -m "spec(agents): detectors" || true
git push -u origin "$branch2" --force-with-lease
