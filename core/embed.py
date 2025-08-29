"""OpenAI embedding helpers.

Use text-embedding-3-small by default.

Batch requests; dedupe by chunk hash to avoid re-embedding.

Store embed_model, embed_version, vector_dim on each chunk.
"""
