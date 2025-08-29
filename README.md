# Argo — The Argonauts SOC Platform

**Argo** is a CLI-first SOC sidecar. We start with **Orpheus (CTI agent)**:
- Ingest threat PDFs → chunk + embed (OpenAI).
- Build actor profiles (aliases, TTPs, CVEs) with **doc/page/bbox citations**.
- Optional exposure (KEV/EPSS; ServiceNow VR if configured).
- **Human-in-loop** approval gate before publish.
- Outputs: **Markdown** report + **JSONL** evidence pack.

## Agents (Crew Status)
- 🪕 **Orpheus** — CTI Agent (**Phase 1 target — ship as finished product**)
- 👁️ **Lynceus** — Exposure (Planned)
- 🏹 **Atalanta** — Detection (Planned)
- 🔨 **Heracles** — IR (Planned)
- ⚔️ **Jason** — Incident Manager (Planned)
- 📜 **Chronicler** — Reporting (Planned)

## Quickstart
```bash
# 0) Prereqs: Docker, Python 3.11+, uv (https://astral.sh/uv)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 1) Infra (Postgres)
docker compose up -d

# 2) Env & deps
cp .env.example .env     # add your OPENAI_API_KEY
uv venv && source .venv/bin/activate
uv pip install -e .

# 3) Initialize DB schema
psql "${PG_DSN:-postgresql://hunter:hunter@localhost:5432/hunter}" -f stores/pg_schema.sql

# 4) See plan & tasks
cat phases/PHASE1_ORPHEUS.md
Tech Stack
Python 3.11+, uv pkg manager

CLI: Typer + Rich

Stores: Postgres (graph/metadata), FAISS-CPU (vectors), filesystem object store

LLM: OpenAI embeddings (text-embedding-3-small default); selective vision (auto, capped)

Retrieval: Hybrid FAISS + BM25 (rank-bm25), citations only

Runbooks: Deterministic flows + approval gate

Security: Local-first, read-only integrations, no secrets in repo

See docs/ARCHITECTURE.md, docs/CONFIG.md, docs/SECRETS.md.
