# Phase 1 — Orpheus (CTI Agent)

## Objective
Ship a finished CLI sidecar that:
- Ingests PDFs → chunks → embeddings (OpenAI).
- Retrieves top-K evidence with citations.
- Builds actor profiles & optional exposure (KEV/EPSS).
- Requires approval before publishing Markdown + JSONL.

## Success Criteria
- `argo run orpheus --actor FIN7` → aliases, ≥3 TTPs, ≥2 CVEs, all claims cited.
- `argo run orpheus --actor FIN7 --exposure` → prioritized CVEs (KEV/EPSS).
- Runs on a clean laptop in <20 min setup.

## Tasks (see tasks/)
01_scaffolding → 02_ingestion → 03_retrieval → 04_orpheus_flow → 05_outputs → 06_cli → 07_watch_folder (opt) → 08_exposure
