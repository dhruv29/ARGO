"""PDF ingest pipeline: PyMuPDF -> OCR (fallback) -> chunk -> persist (PG) -> embed (OpenAI) -> index (FAISS)."""
