"""Local embedding alternatives to OpenAI for air-gapped environments."""

import os
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path
import numpy as np

logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available. Install with: pip install sentence-transformers")

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available. Install with: pip install torch")


class LocalEmbeddingManager:
    """Manage local embedding models for air-gapped environments."""
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize local embedding manager.
        
        Args:
            model_name: Name of the sentence-transformers model to use
        """
        self.model_name = model_name
        self.model = None
        self.model_dimension = None
        
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            self._load_model()
        else:
            logger.error("sentence-transformers not available. Cannot use local embeddings.")
    
    def _load_model(self):
        """Load the sentence transformer model."""
        try:
            logger.info(f"Loading local embedding model: {self.model_name}")
            self.model = SentenceTransformer(self.model_name)
            
            # Get model dimension
            test_embedding = self.model.encode("test", convert_to_tensor=False)
            self.model_dimension = len(test_embedding)
            
            logger.info(f"Loaded model with dimension: {self.model_dimension}")
            
        except Exception as e:
            logger.error(f"Failed to load local embedding model: {e}")
            self.model = None
    
    def generate_embeddings(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """
        Generate embeddings for a list of texts.
        
        Args:
            texts: List of text strings to embed
            batch_size: Batch size for processing
            
        Returns:
            List of embedding vectors
        """
        if not self.model:
            logger.error("Local embedding model not loaded")
            return []
        
        try:
            embeddings = []
            
            # Process in batches
            for i in range(0, len(texts), batch_size):
                batch = texts[i:i + batch_size]
                batch_embeddings = self.model.encode(batch, convert_to_tensor=False)
                
                # Convert to list format
                for emb in batch_embeddings:
                    embeddings.append(emb.tolist())
            
            logger.info(f"Generated {len(embeddings)} local embeddings")
            return embeddings
            
        except Exception as e:
            logger.error(f"Failed to generate local embeddings: {e}")
            return []
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        return {
            "model_name": self.model_name,
            "dimension": self.model_dimension,
            "available": self.model is not None,
            "dependencies": {
                "sentence_transformers": SENTENCE_TRANSFORMERS_AVAILABLE,
                "torch": TORCH_AVAILABLE
            }
        }


def get_local_embedding_config() -> Dict[str, Any]:
    """Get configuration for local embeddings."""
    return {
        "model_name": os.getenv("LOCAL_EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
        "batch_size": int(os.getenv("LOCAL_EMBEDDING_BATCH_SIZE", "32")),
        "device": os.getenv("LOCAL_EMBEDDING_DEVICE", "cpu")
    }


def generate_local_embeddings_batch(
    texts: List[str], 
    config: Optional[Dict[str, Any]] = None
) -> List[List[float]]:
    """
    Generate embeddings using local model.
    
    Args:
        texts: List of text strings to embed
        config: Configuration dictionary
    
    Returns:
        List of embedding vectors
    """
    if not config:
        config = get_local_embedding_config()
    
    manager = LocalEmbeddingManager(config["model_name"])
    return manager.generate_embeddings(texts, config["batch_size"])


# Model recommendations for CTI semantics
RECOMMENDED_MODELS = {
    "fast": {
        "name": "all-MiniLM-L6-v2",
        "dimension": 384,
        "speed": "fast",
        "quality": "good",
        "memory": "low"
    },
    "balanced": {
        "name": "all-mpnet-base-v2",
        "dimension": 768,
        "speed": "medium",
        "quality": "excellent",
        "memory": "medium"
    },
    "high_quality": {
        "name": "all-MiniLM-L12-v2",
        "dimension": 384,
        "speed": "medium",
        "quality": "excellent",
        "memory": "medium"
    }
}


def get_model_recommendation(priority: str = "balanced") -> Dict[str, Any]:
    """
    Get model recommendation based on priority.
    
    Args:
        priority: "fast", "balanced", or "high_quality"
    
    Returns:
        Model configuration
    """
    if priority not in RECOMMENDED_MODELS:
        priority = "balanced"
    
    return RECOMMENDED_MODELS[priority]
