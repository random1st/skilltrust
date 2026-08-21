.PHONY: setup format lint typecheck test schemas security check

setup:
	uv sync --all-extras

format:
	uv run ruff format src tests
	uv run ruff check --fix src tests

lint:
	uv run ruff format --check src tests
	uv run ruff check src tests

typecheck:
	uv run mypy src

test:
	uv run pytest

schemas:
	uv run python -m skilltrust.schemas schemas

security:
	scripts/security-audit.sh

check: lint typecheck test
