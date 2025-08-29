
Task 02 — Ingestion
Scope

Parse PDF (PyMuPDF), OCR fallback (only when no text layer).

Chunk (300–800 tokens, ~10–15% overlap).

Tag entities (actors/ttps/cves) via regex/dicts (seed minimal).

Persist documents + chunks in Postgres.

Save original PDFs in OBJECT_STORE_DIR.

Acceptance

Ingest 3 sample PDFs → rows in document + doc_chunk.

OCR pages have confidence; low-confidence chunks flagged weak.
