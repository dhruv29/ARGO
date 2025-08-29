.PHONY: dev-up dev-down install lint fmt test status

dev-up:
docker compose up -d

dev-down:
docker compose down

install:
uv venv || true
. .venv/bin/activate && uv pip install -e .

lint:
ruff check .

fmt:
ruff check --fix .

test:
pytest -q

status:
psql "$$PG_DSN" -c "select now(), current_database();" || true
