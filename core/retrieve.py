"""Hybrid retrieval: FAISS + BM25; Evidence objects with citations.

Query type classify (actor|cve|ttp|general) via regex/dicts.

Prefilter candidate sets using Postgres (aliases, synonyms).

Score normalize FAISS/BM25; interleave; apply MMR diversification.

Return evidence: {doc_id, page, bbox, snippet, score, confidence, tlp, namespace}.
"""
