# 🔐 SecretScan360

**SecretScan360** is a pluggable, fast secrets scanner built for modern CI/CD pipelines.  
It helps detect leaked API keys, private keys, and credentials in source code before they reach production.

## 🚀 Features
- Scan GitHub repositories or local code for secrets
- Detect private keys, API tokens, and common credential patterns
- Store results in Postgres for auditing
- Lightweight microservice architecture (FastAPI + LiteLLM + Agents)
- Designed for integration into CI/CD workflows (GitHub Actions, GitLab CI, Jenkins)

## 📦 Quickstart

```bash
git clone https://github.com/mohan-ai-labs/secret-scan-360.git
cd secret-scan-360

# Copy .env template
cp .env.example .env

# Start services
docker compose up -d

# Check health
curl http://localhost:8000/health

