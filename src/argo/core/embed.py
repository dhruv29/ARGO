

"""OpenAI embedding helpers; batch; store embed_model/version/dim on chunks."""

import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import numpy as np
from tenacity import retry, stop_after_attempt, wait_exponential
from dotenv import load_dotenv

import openai
import psycopg
from pydantic import BaseModel

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class EmbeddingConfig:
    """Configuration for embedding generation."""
    model: str = "text-embedding-3-small"
    dimensions: int = 1536
    batch_size: int = 100
    max_tokens: int = 8191  # Max tokens for text-embedding-3-small


class ChunkEmbedding(BaseModel):
    """Embedding data for a document chunk."""
    chunk_id: str
    embedding: List[float]
    model: str
    version: str
    dimensions: int


def get_embedding_config() -> EmbeddingConfig:
    """Get embedding configuration from environment."""
    model = os.getenv("EMBED_MODEL", "text-embedding-3-small")
    
    # Set dimensions based on model
    if model == "text-embedding-3-small":
        dimensions = 1536
    elif model == "text-embedding-3-large":
        dimensions = 3072
    elif model == "text-embedding-ada-002":
        dimensions = 1536
    else:
        dimensions = 1536  # Default
    
    return EmbeddingConfig(
        model=model,
        dimensions=dimensions,
        batch_size=int(os.getenv("EMBED_BATCH_SIZE", "100")),
        max_tokens=8191
    )


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def generate_embeddings_batch(
    texts: List[str], 
    config: EmbeddingConfig,
    client: openai.OpenAI
) -> List[List[float]]:
    """
    Generate embeddings for a batch of texts using OpenAI API.
    
    Args:
        texts: List of text strings to embed
        config: Embedding configuration
        client: OpenAI client instance
    
    Returns:
        List of embedding vectors
    """
    try:
        # Truncate texts that are too long
        truncated_texts = []
        for text in texts:
            # Simple token approximation: ~4 chars per token
            if len(text) > config.max_tokens * 4:
                truncated_text = text[:config.max_tokens * 4]
                logger.warning(f"Truncated text from {len(text)} to {len(truncated_text)} characters")
                truncated_texts.append(truncated_text)
            else:
                truncated_texts.append(text)
        
        response = client.embeddings.create(
            model=config.model,
            input=truncated_texts,
            dimensions=config.dimensions
        )
        
        embeddings = [item.embedding for item in response.data]
        logger.info(f"Generated {len(embeddings)} embeddings using {config.model}")
        
        return embeddings
        
    except Exception as e:
        logger.error(f"Failed to generate embeddings: {e}")
        raise


def embed_chunks(
    chunks: List[Dict[str, Any]], 
    db_url: str,
    config: Optional[EmbeddingConfig] = None
) -> List[ChunkEmbedding]:
    """
    Generate embeddings for document chunks and store them in the database.
    
    Args:
        chunks: List of chunk dictionaries with 'id' and 'text' keys
        db_url: PostgreSQL connection URL
        config: Embedding configuration (optional)
    
    Returns:
        List of ChunkEmbedding objects
    """
    if not chunks:
        return []
    
    if config is None:
        config = get_embedding_config()
    
    # Initialize OpenAI client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OpenAI API key not found in environment variables")
    
    client = openai.OpenAI(api_key=api_key)
    
    # Get model version for tracking
    model_version = "v1"  # You might want to get this from OpenAI API
    
    chunk_embeddings = []
    
    # Process chunks in batches
    for i in range(0, len(chunks), config.batch_size):
        batch = chunks[i:i + config.batch_size]
        batch_texts = [chunk["text"] for chunk in batch]
        batch_ids = [chunk["id"] for chunk in batch]
        
        logger.info(f"Processing embedding batch {i//config.batch_size + 1}: {len(batch)} chunks")
        
        # Generate embeddings
        embeddings = generate_embeddings_batch(batch_texts, config, client)
        
        # Create ChunkEmbedding objects
        for chunk_id, embedding in zip(batch_ids, embeddings):
            chunk_embedding = ChunkEmbedding(
                chunk_id=chunk_id,
                embedding=embedding,
                model=config.model,
                version=model_version,
                dimensions=config.dimensions
            )
            chunk_embeddings.append(chunk_embedding)
    
    # Store embeddings in database
    store_embeddings_in_db(chunk_embeddings, db_url)
    
    logger.info(f"Generated and stored {len(chunk_embeddings)} embeddings")
    return chunk_embeddings


def store_embeddings_in_db(embeddings: List[ChunkEmbedding], db_url: str) -> None:
    """Store embeddings in the database by updating doc_chunk table."""
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            for embedding in embeddings:
                cur.execute("""
                    UPDATE doc_chunk 
                    SET 
                        embed_model = %s,
                        embed_version = %s,
                        vector_dim = %s,
                        embedding = %s
                    WHERE id = %s
                """, (
                    embedding.model,
                    embedding.version,
                    embedding.dimensions,
                    embedding.embedding,  # PostgreSQL will handle list to array conversion
                    embedding.chunk_id
                ))
        
        conn.commit()
        logger.info(f"Stored {len(embeddings)} embeddings in database")


def get_chunks_without_embeddings(db_url: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Get chunks that don't have embeddings yet.
    
    Args:
        db_url: PostgreSQL connection URL
        limit: Maximum number of chunks to return (optional)
    
    Returns:
        List of chunk dictionaries with 'id' and 'text' keys
    """
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            query = """
                SELECT id, text 
                FROM doc_chunk 
                WHERE embed_model IS NULL OR embed_version IS NULL
                ORDER BY created_at
            """
            
            if limit:
                query += f" LIMIT {limit}"
            
            cur.execute(query)
            rows = cur.fetchall()
            
            chunks = [{"id": row[0], "text": row[1]} for row in rows]
            logger.info(f"Found {len(chunks)} chunks without embeddings")
            
            return chunks


def embed_all_chunks(db_url: str, batch_size: Optional[int] = None) -> int:
    """
    Generate embeddings for all chunks that don't have them yet.
    
    Args:
        db_url: PostgreSQL connection URL
        batch_size: Number of chunks to process at once (optional)
    
    Returns:
        Number of chunks processed
    """
    config = get_embedding_config()
    if batch_size:
        config.batch_size = batch_size
    
    chunks_without_embeddings = get_chunks_without_embeddings(db_url)
    
    if not chunks_without_embeddings:
        logger.info("All chunks already have embeddings")
        return 0
    
    logger.info(f"Found {len(chunks_without_embeddings)} chunks to embed")
    
    # Process all chunks
    embed_chunks(chunks_without_embeddings, db_url, config)
    
    return len(chunks_without_embeddings)


def get_embedding_stats(db_url: str) -> Dict[str, Any]:
    """Get statistics about embeddings in the database."""
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            # Get total chunks
            cur.execute("SELECT COUNT(*) FROM doc_chunk")
            total_chunks = cur.fetchone()[0]
            
            # Get chunks with embeddings
            cur.execute("""
                SELECT COUNT(*) FROM doc_chunk 
                WHERE embed_model IS NOT NULL AND embed_version IS NOT NULL
            """)
            embedded_chunks = cur.fetchone()[0]
            
            # Get embedding models used
            cur.execute("""
                SELECT embed_model, COUNT(*) 
                FROM doc_chunk 
                WHERE embed_model IS NOT NULL 
                GROUP BY embed_model
            """)
            model_stats = dict(cur.fetchall())
            
            return {
                "total_chunks": total_chunks,
                "embedded_chunks": embedded_chunks,
                "pending_chunks": total_chunks - embedded_chunks,
                "completion_rate": embedded_chunks / total_chunks if total_chunks > 0 else 0,
                "models_used": model_stats
            }