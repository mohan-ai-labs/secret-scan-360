
.PHONY: up down docker-build init-db health scan docker-clean logs build clean release-testpypi release-pypi

ENV_FILE ?= .env

up: ## Start all services
	docker compose --env-file $(ENV_FILE) up -d

down: ## Stop all services (keep volumes)
	docker compose --env-file $(ENV_FILE) down

docker-build: ## Build images
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

docker-clean: ## Stop and remove Docker volumes (DANGEROUS)
	docker compose --env-file $(ENV_FILE) down -v

# Python packaging targets
build: ## Build Python wheel and sdist
	python -m build --no-isolation

clean: ## Clean Python build artifacts
	rm -rf build/ dist/ *.egg-info/ src/*.egg-info/

release-testpypi: build ## Build and upload to TestPyPI
	python -m twine upload --repository testpypi dist/*

release-pypi: build ## Build and upload to PyPI
	python -m twine upload dist/*
