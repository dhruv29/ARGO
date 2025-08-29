# Argo — The Argonauts SOC Platform

**Argo** is a CLI-first SOC sidecar. Phase-1 ships **Orpheus (CTI agent)**:
- Ingest threat PDFs → chunk + embed (OpenAI).
- Retrieve evidence with **doc/page/bbox** citations.
- Build actor profiles (aliases, TTPs, CVEs) with a **human approval gate**.
- Optional exposure view (KEV/EPSS; ServiceNow VR if configured).
- Outputs: **Markdown** report + **JSONL** evidence pack.

### Deterministic-first, with guarded LLM fallback
Orpheus always prefers **deterministic sources** (seeded Postgres → ATT&CK/MISP sync).  
If an actor is unknown, Orpheus can run a **RAG-extraction fallback** over your **local ingested PDFs** to propose aliases.  
New aliases are **shown with citations** and only **written to the graph on analyst approval**.  
This keeps the sidecar **fast, auditable, and low-risk** while avoiding dead ends.

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
### Tech Stack
Python 3.11 • Typer • LangGraph • Postgres • FAISS-CPU • PyMuPDF • rank-BM25 • OpenAI embeddings

See docs/ARCHITECTURE.md, docs/CONFIG.md, docs/SECRETS.md.
