# Task 07 — Watch Folder (Optional)

## Scope
- `argo watch ./intel_reports` to auto-ingest new PDFs.
- Debounce + SHA256 idempotency.

## Acceptance
- Dropping a PDF ingests it exactly once and prints stats.
