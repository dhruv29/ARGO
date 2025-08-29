# Task 02 — Ingestion

## Scope
- Parse PDF (PyMuPDF), OCR fallback only if no text layer.
- Chunk (300–800 tokens, ~10–15% overlap).
- Tag entities via regex/dicts (actors/ttps/cves) — seed minimal.
- Persist `document` + `doc_chunk`; save PDFs to object store.

## Acceptance
- Ingest 3 sample PDFs → rows in `document` + `doc_chunk`.
- OCR pages have `confidence`; low-confidence chunks flagged `weak`.
