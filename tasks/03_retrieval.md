# Task 03 — Retrieval

## Scope
- OpenAI embeddings (batch); store model/version/dim.
- FAISS HNSW index (persist/load).
- BM25 fallback; score normalization + interleave; MMR diversification.
- Evidence object: doc/page/bbox/snippet/score/confidence/tlp.

## Acceptance
- Search "CVE-2023-23397" returns ≥8 cited chunks across ≥2 docs.
