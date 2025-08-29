# Task 01 — Scaffolding

## Scope
Repo structure, env, deps, infra (Postgres), schema apply.

## Steps
- Ensure dirs exist (cli/core/stores/agents/mcp/docs/tasks/phases/samples/object_store/reports/flows).
- `uv venv && source .venv/bin/activate && uv pip install -e .`
- `docker compose up -d`
- `psql "$PG_DSN" -f stores/pg_schema.sql`

## Acceptance
- Tables created; env + deps installed; Postgres healthy.
