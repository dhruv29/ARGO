
Task 01 — Scaffolding
Scope

Repo structure, env, deps, infra (Postgres), schema apply.

Steps

Ensure dirs exist (cli/core/stores/agents/mcp/docs/tasks/phases/samples/object_store/reports/flows).

Fill repo with README, docs, phases, tasks.

uv venv && uv pip install -e .

docker compose up -d

psql "$PG_DSN" -f stores/pg_schema.sql

Acceptance

psql shows tables created; repo has all docs; uv pip installed.
