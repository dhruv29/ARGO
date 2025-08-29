# Config

## Core
- `EMBED_MODEL` = `text-embedding-3-small` (default)
- `VISION_MODE` = `auto`  (`off|auto|on`)
- `VISION_MAX_CALLS_PER_DOC` = `4`

## Stores
- `PG_DSN` = `postgresql://hunter:hunter@localhost:5432/hunter`
- `OBJECT_STORE_DIR` = `./object_store`

## Retrieval
- `TOP_K` = `15`
- `BM25_ENABLED` = `true`
- `FAISS_INDEX` = `HNSW`

## Dual-RAG (defaults are conservative)
- `RAG_ORDER` = `personal,global`
- `RAG_WEIGHT_PERSONAL` = `0.7`
- `RAG_WEIGHT_GLOBAL` = `0.3`
- `SHARE_DEFAULT` = `deny`
- `ALLOW_TLP` = `CLEAR,GREEN`
