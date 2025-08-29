
Architecture (Phase 1 — Orpheus)

CLI: Typer + Rich → argo run orpheus.

Core: ingest (PyMuPDF, OCR fallback), chunk, embed (OpenAI), retrieve (FAISS+BM25).

Stores: Postgres (graph/metadata), FAISS CPU (vectors), filesystem object store.

Evidence: doc/page/bbox/snippet/score/confidence/tlp.

Approval: single gate before report publish.

Outputs: Markdown report + JSONL evidence.

Non-negotiables: citations for every claim; analyst approval; local-first.
