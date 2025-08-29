"""PDF ingest pipeline: PyMuPDF -> OCR (optional) -> chunk -> persist (PG) -> embed (OpenAI) -> index (FAISS).

Guidelines to implement:

Use PyMuPDF for text + bbox; detect pages with no text layer.

OCR only those pages (record 'confidence'); skip low-confidence in evidence by default.

Chunk size: 300–800 tokens with ~10–15% overlap.

Store doc + chunk rows; keep doc/page/bbox/snippet for citations.

Batch embeddings; store embed_model/version/dim.
"""
