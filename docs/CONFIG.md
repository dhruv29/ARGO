
Config

Embeddings: EMBED_MODEL=text-embedding-3-small (switch to -large for audits).

Vision: VISION_MODE=auto, VISION_MAX_CALLS_PER_DOC=4 (only for scanned/diagram pages).

Retrieval: TOP_K=15, BM25_ENABLED=true, FAISS_INDEX=HNSW.

Stores: PG_DSN, OBJECT_STORE_DIR.

Dual-RAG knobs (Phase 1 defaults to personal first):

RAG_ORDER=personal,global, weights 0.7/0.3.

Sharing: SHARE_DEFAULT=deny, ALLOW_TLP=CLEAR,GREEN.
