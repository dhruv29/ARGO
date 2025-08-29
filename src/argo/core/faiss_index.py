"""FAISS HNSW index creation, persistence, and loading for document embeddings."""

import os
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from dotenv import load_dotenv

import faiss
import psycopg
from pydantic import BaseModel

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class FAISSConfig:
    """Configuration for FAISS index."""
    def __init__(self):
        self.index_type = os.getenv("FAISS_INDEX", "HNSW")
        self.dimensions = 1536  # text-embedding-3-small default
        self.hnsw_m = 16  # Number of bidirectional links for HNSW
        self.hnsw_ef_construction = 200  # Size of dynamic candidate list for HNSW
        self.hnsw_ef_search = 100  # Size of dynamic candidate list for search


class FAISSIndexManager:
    """Manages FAISS index operations."""
    
    def __init__(self, index_path: Path, config: Optional[FAISSConfig] = None):
        self.index_path = index_path
        self.config = config or FAISSConfig()
        self.index: Optional[faiss.Index] = None
        self.chunk_id_map: Dict[int, str] = {}  # Maps FAISS ID to chunk ID
        self.reverse_chunk_map: Dict[str, int] = {}  # Maps chunk ID to FAISS ID
    
    def create_index(self, dimensions: int) -> faiss.Index:
        """Create a new FAISS index."""
        if self.config.index_type == "HNSW":
            # Create HNSW index (good for high-dimensional data)
            index = faiss.IndexHNSWFlat(dimensions, self.config.hnsw_m)
            index.hnsw.efConstruction = self.config.hnsw_ef_construction
            index.hnsw.efSearch = self.config.hnsw_ef_search
            
            logger.info(f"Created HNSW index with dimensions={dimensions}, M={self.config.hnsw_m}")
        else:
            # Fallback to flat index
            index = faiss.IndexFlatIP(dimensions)  # Inner product (cosine similarity)
            logger.info(f"Created flat index with dimensions={dimensions}")
        
        return index
    
    def load_index(self) -> bool:
        """Load existing FAISS index from disk."""
        index_file = self.index_path / "faiss.index"
        metadata_file = self.index_path / "metadata.txt"
        
        if not index_file.exists() or not metadata_file.exists():
            logger.info("No existing FAISS index found")
            return False
        
        try:
            # Load FAISS index
            self.index = faiss.read_index(str(index_file))
            
            # Load chunk ID mapping
            with open(metadata_file, 'r') as f:
                for line in f:
                    faiss_id, chunk_id = line.strip().split('\t')
                    faiss_id = int(faiss_id)
                    self.chunk_id_map[faiss_id] = chunk_id
                    self.reverse_chunk_map[chunk_id] = faiss_id
            
            logger.info(f"Loaded FAISS index with {self.index.ntotal} vectors")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load FAISS index: {e}")
            return False
    
    def save_index(self) -> None:
        """Save FAISS index to disk."""
        if self.index is None:
            raise ValueError("No index to save")
        
        self.index_path.mkdir(parents=True, exist_ok=True)
        
        index_file = self.index_path / "faiss.index"
        metadata_file = self.index_path / "metadata.txt"
        
        # Save FAISS index
        faiss.write_index(self.index, str(index_file))
        
        # Save chunk ID mapping
        with open(metadata_file, 'w') as f:
            for faiss_id, chunk_id in self.chunk_id_map.items():
                f.write(f"{faiss_id}\t{chunk_id}\n")
        
        logger.info(f"Saved FAISS index with {self.index.ntotal} vectors to {self.index_path}")
    
    def add_embeddings(self, embeddings: np.ndarray, chunk_ids: List[str]) -> None:
        """Add embeddings to the index."""
        if len(embeddings) != len(chunk_ids):
            raise ValueError("Number of embeddings must match number of chunk IDs")
        
        if self.index is None:
            # Create new index
            dimensions = embeddings.shape[1]
            self.index = self.create_index(dimensions)
        
        # Normalize embeddings for cosine similarity (if using IP index)
        if isinstance(self.index, faiss.IndexFlatIP) or "IP" in str(type(self.index)):
            embeddings = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)
        
        # Get starting FAISS ID
        start_id = self.index.ntotal
        
        # Add to index
        self.index.add(embeddings.astype(np.float32))
        
        # Update mappings
        for i, chunk_id in enumerate(chunk_ids):
            faiss_id = start_id + i
            self.chunk_id_map[faiss_id] = chunk_id
            self.reverse_chunk_map[chunk_id] = faiss_id
        
        logger.info(f"Added {len(embeddings)} embeddings to FAISS index")
    
    def search(self, query_embedding: np.ndarray, k: int = 10) -> List[Tuple[str, float]]:
        """Search the index for similar embeddings."""
        if self.index is None:
            raise ValueError("No index loaded")
        
        # Normalize query embedding if using IP index
        if isinstance(self.index, faiss.IndexFlatIP) or "IP" in str(type(self.index)):
            query_embedding = query_embedding / np.linalg.norm(query_embedding)
        
        # Ensure query is 2D
        if query_embedding.ndim == 1:
            query_embedding = query_embedding.reshape(1, -1)
        
        # Search
        scores, indices = self.index.search(query_embedding.astype(np.float32), k)
        
        # Convert results
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx != -1 and idx in self.chunk_id_map:  # -1 means not found
                chunk_id = self.chunk_id_map[idx]
                results.append((chunk_id, float(score)))
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get index statistics."""
        if self.index is None:
            return {"total_vectors": 0, "index_type": "None"}
        
        return {
            "total_vectors": self.index.ntotal,
            "index_type": str(type(self.index).__name__),
            "dimensions": self.index.d if hasattr(self.index, 'd') else None,
            "mapped_chunks": len(self.chunk_id_map)
        }


def get_embeddings_from_db(db_url: str, chunk_ids: Optional[List[str]] = None) -> Tuple[np.ndarray, List[str]]:
    """
    Get embeddings from database.
    
    Args:
        db_url: PostgreSQL connection URL
        chunk_ids: Optional list of specific chunk IDs to get
    
    Returns:
        Tuple of (embeddings array, chunk_ids list)
    """
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            if chunk_ids:
                # Get specific chunks
                placeholders = ','.join(['%s'] * len(chunk_ids))
                query = f"""
                    SELECT id, embedding 
                    FROM doc_chunk 
                    WHERE id IN ({placeholders}) 
                    AND embedding IS NOT NULL
                    ORDER BY id
                """
                cur.execute(query, chunk_ids)
            else:
                # Get all chunks with embeddings
                query = """
                    SELECT id, embedding 
                    FROM doc_chunk 
                    WHERE embedding IS NOT NULL
                    ORDER BY id
                """
                cur.execute(query)
            
            rows = cur.fetchall()
            
            if not rows:
                logger.info("No embeddings found in database")
                return np.array([]), []
            
            # Extract embeddings and chunk IDs
            chunk_ids_result = []
            embeddings_list = []
            
            for chunk_id, embedding in rows:
                if embedding:  # Make sure embedding is not None
                    chunk_ids_result.append(chunk_id)
                    embeddings_list.append(embedding)
            
            if not embeddings_list:
                logger.info("No valid embeddings found in database")
                return np.array([]), []
            
            # Convert to numpy array
            embeddings_array = np.array(embeddings_list, dtype=np.float32)
            
            logger.info(f"Retrieved {len(embeddings_array)} embeddings from database")
            return embeddings_array, chunk_ids_result


def build_faiss_index(db_url: str, index_path: Path, force_rebuild: bool = False) -> FAISSIndexManager:
    """
    Build or load FAISS index from database embeddings.
    
    Args:
        db_url: PostgreSQL connection URL
        index_path: Path to store/load index
        force_rebuild: Whether to rebuild index even if it exists
    
    Returns:
        FAISSIndexManager instance
    """
    manager = FAISSIndexManager(index_path)
    
    # Try to load existing index
    if not force_rebuild and manager.load_index():
        logger.info("Loaded existing FAISS index")
        return manager
    
    logger.info("Building new FAISS index from database embeddings")
    
    # Get embeddings from database
    # Note: This is a placeholder since we don't store embeddings in the DB yet
    # In a real implementation, you would retrieve the actual embedding vectors
    embeddings, chunk_ids = get_embeddings_from_db(db_url)
    
    if len(embeddings) == 0:
        logger.warning("No embeddings found in database - creating empty index")
        # Create empty index for future use
        manager.index = manager.create_index(1536)  # Default dimensions
    else:
        # Add embeddings to index
        manager.add_embeddings(embeddings, chunk_ids)
    
    # Save index
    manager.save_index()
    
    return manager


def search_faiss(
    query_embedding: np.ndarray, 
    k: int, 
    index_path: Path,
    namespace: str = "personal"
) -> List[Dict[str, Any]]:
    """
    Search FAISS index for similar chunks.
    
    Args:
        query_embedding: Query embedding vector
        k: Number of results to return
        index_path: Path to FAISS index
        namespace: Namespace filter (for future use)
    
    Returns:
        List of search results with chunk IDs and scores
    """
    manager = FAISSIndexManager(index_path)
    
    if not manager.load_index():
        logger.warning("No FAISS index found")
        return []
    
    # Search
    results = manager.search(query_embedding, k)
    
    # Convert to expected format
    search_results = []
    for chunk_id, score in results:
        search_results.append({
            "chunk_id": chunk_id,
            "score": score,
            "source": "faiss"
        })
    
    return search_results
