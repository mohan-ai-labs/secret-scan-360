
.PHONY: up down build init-db health scan clean logs

ENV_FILE ?= .env

up: ## Start all services
	docker compose --env-file $(ENV_FILE) up -d

down: ## Stop all services (keep volumes)
	docker compose --env-file $(ENV_FILE) down

build: ## Build images
	docker compose --env-file $(ENV_FILE) build

init-db: ## Apply schema to Postgres
	docker compose --env-file $(ENV_FILE) exec -T postgres psql -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -f /dev/stdin < sql_init.sql

health: ## Check health endpoints
	@echo "API:" && curl -s http://localhost:8000/health || true
	@echo "\nAGENTS:" && curl -s http://localhost:8080/health || true

scan: ## Trigger a demo scan (Vault repo)
	curl -s -X POST http://localhost:8000/scan -H 'content-type: application/json' -d '{"repo_url":"https://github.com/hashicorp/vault"}' | head -c 400; echo

logs: ## Tail logs
	docker compose --env-file $(ENV_FILE) logs -f

clean: ## Stop and remove volumes (DANGEROUS)
	docker compose --env-file $(ENV_FILE) down -v
