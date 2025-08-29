"""Hybrid retrieval system: FAISS + BM25 with MMR diversification."""

import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass
from dotenv import load_dotenv
import numpy as np

import psycopg
from rank_bm25 import BM25Okapi
from pydantic import BaseModel

from .embed import get_embedding_config, generate_embeddings_batch
from .faiss_index import FAISSIndexManager
import openai

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class Evidence:
    """Evidence object containing search result metadata."""
    chunk_id: str
    document_id: str
    page: int
    bbox: List[float]
    snippet: str
    score: float
    confidence: float
    tlp: str
    namespace: str
    source: str  # "faiss" or "bm25"
    actors: List[str] = None
    techniques: List[str] = None
    cves: List[str] = None


def classify_query(q: str) -> str:
    """Classify query type for optimized search."""
    query_lower = q.lower()
    
    # CVE pattern
    if re.search(r'cve-\d{4}-\d{4,}', query_lower):
        return "cve"
    
    # MITRE ATT&CK technique pattern
    if re.search(r't\d{4}(\.\d{3})?', query_lower):
        return "ttp"
    
    # Common actor indicators
    actor_keywords = ['apt', 'group', 'actor', 'team', 'campaign']
    if any(keyword in query_lower for keyword in actor_keywords):
        return "actor"
    
    return "general"


def prefilter_terms(qtype: str, q: str, db_url: str) -> Dict[str, Any]:
    """Return aliases/synonyms/filters from database to shrink search space."""
    filters = {}
    
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            if qtype == "actor":
                # Look for actor aliases
                cur.execute("""
                    SELECT names FROM actor 
                    WHERE %s = ANY(names) OR id ILIKE %s
                """, (q, f"%{q}%"))
                
                rows = cur.fetchall()
                if rows:
                    all_names = set()
                    for row in rows:
                        all_names.update(row[0] or [])
                    filters['actor_aliases'] = list(all_names)
            
            elif qtype == "ttp":
                # Look for technique synonyms
                cur.execute("""
                    SELECT synonyms FROM technique 
                    WHERE t_id = %s OR %s = ANY(synonyms)
                """, (q, q))
                
                rows = cur.fetchall()
                if rows:
                    all_synonyms = set()
                    for row in rows:
                        all_synonyms.update(row[0] or [])
                    filters['ttp_synonyms'] = list(all_synonyms)
    
    return filters


def search_faiss(query_vec: np.ndarray, k: int, namespace: str = "personal") -> List[Evidence]:
    """Search FAISS index and return Evidence objects."""
    from .faiss_index import search_faiss as faiss_search
    index_path = Path("./faiss_index")
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    # Use the faiss_index module function
    results = faiss_search(query_vec, k, index_path, namespace)
    
    evidence_list = []
    chunk_ids = [r["chunk_id"] for r in results]
    
    if not chunk_ids:
        return evidence_list
    
    # Get full chunk details from database
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            placeholders = ','.join(['%s'] * len(chunk_ids))
            cur.execute(f"""
                SELECT dc.id, dc.document_id, dc.page, dc.bbox, dc.text,
                       dc.actors, dc.techniques, dc.cves, dc.confidence,
                       d.tlp, d.namespace
                FROM doc_chunk dc
                JOIN document d ON dc.document_id = d.id
                WHERE dc.id IN ({placeholders})
            """, chunk_ids)
            
            rows = cur.fetchall()
    
    # Create Evidence objects
    chunk_details = {row[0]: row for row in rows}
    
    for result in results:
        chunk_id = result["chunk_id"]
        score = result["score"]
        
        if chunk_id not in chunk_details:
            continue
        
        row = chunk_details[chunk_id]
        _, doc_id, page, bbox, text, actors, techniques, cves, confidence, tlp, ns = row
        
        snippet = text[:200] + "..." if len(text) > 200 else text
        
        evidence = Evidence(
            chunk_id=chunk_id,
            document_id=doc_id,
            page=page,
            bbox=bbox or [],
            snippet=snippet,
            score=float(score),
            confidence=confidence or 1.0,
            tlp=tlp or 'CLEAR',
            namespace=ns or 'personal',
            source="faiss",
            actors=actors or [],
            techniques=techniques or [],
            cves=cves or []
        )
        
        evidence_list.append(evidence)
    
    return evidence_list


def search_bm25(query_text: str, k: int, namespace: str = "personal") -> List[Evidence]:
    """Search using BM25 keyword matching."""
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    with psycopg.connect(db_url) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT dc.id, dc.document_id, dc.page, dc.bbox, dc.text,
                       dc.actors, dc.techniques, dc.cves, dc.confidence,
                       d.tlp, d.namespace
                FROM doc_chunk dc
                JOIN document d ON dc.document_id = d.id
                WHERE dc.text IS NOT NULL AND dc.text != ''
                AND d.namespace = %s
                ORDER BY dc.id
            """, (namespace,))
            
            rows = cur.fetchall()
    
    if not rows:
        return []
    
    # Prepare texts for BM25
    texts = []
    chunk_data = []
    
    for row in rows:
        chunk_id, doc_id, page, bbox, text, actors, techniques, cves, confidence, tlp, ns = row
        
        # Simple tokenization
        tokens = re.sub(r'[^\w\s-]', ' ', text.lower()).split()
        tokens = [t for t in tokens if len(t) > 2]
        
        texts.append(tokens)
        chunk_data.append({
            'chunk_id': chunk_id,
            'document_id': doc_id,
            'page': page,
            'bbox': bbox or [],
            'text': text,
            'actors': actors or [],
            'techniques': techniques or [],
            'cves': cves or [],
            'confidence': confidence or 1.0,
            'tlp': tlp or 'CLEAR',
            'namespace': ns or 'personal'
        })
    
    # Build BM25 index
    bm25 = BM25Okapi(texts)
    
    # Tokenize query
    query_tokens = re.sub(r'[^\w\s-]', ' ', query_text.lower()).split()
    query_tokens = [t for t in query_tokens if len(t) > 2]
    
    if not query_tokens:
        return []
    
    # Get scores
    scores = bm25.get_scores(query_tokens)
    
    # Get top results
    top_indices = np.argsort(scores)[::-1][:k]
    
    results = []
    for idx in top_indices:
        if scores[idx] <= 0:
            break
        
        chunk = chunk_data[idx]
        snippet = chunk['text'][:200] + "..." if len(chunk['text']) > 200 else chunk['text']
        
        evidence = Evidence(
            chunk_id=chunk['chunk_id'],
            document_id=chunk['document_id'],
            page=chunk['page'],
            bbox=chunk['bbox'],
            snippet=snippet,
            score=float(scores[idx]),
            confidence=chunk['confidence'],
            tlp=chunk['tlp'],
            namespace=chunk['namespace'],
            source="bm25",
            actors=chunk['actors'],
            techniques=chunk['techniques'],
            cves=chunk['cves']
        )
        
        results.append(evidence)
    
    return results


def normalize_and_merge(hits_vec: List[Evidence], hits_kw: List[Evidence]) -> List[Evidence]:
    """Normalize scores and merge FAISS and BM25 results."""
    all_hits = []
    
    # Normalize FAISS scores (already 0-1 range for cosine similarity)
    for hit in hits_vec:
        hit.score = min(max(hit.score, 0.0), 1.0)
        all_hits.append(hit)
    
    # Normalize BM25 scores to [0,1] range
    if hits_kw:
        max_bm25_score = max(hit.score for hit in hits_kw)
        if max_bm25_score > 0:
            for hit in hits_kw:
                hit.score = hit.score / max_bm25_score
                all_hits.append(hit)
    
    # Remove duplicates (prefer higher score)
    seen_chunks = {}
    for hit in all_hits:
        if hit.chunk_id not in seen_chunks or hit.score > seen_chunks[hit.chunk_id].score:
            seen_chunks[hit.chunk_id] = hit
    
    merged_hits = list(seen_chunks.values())
    merged_hits.sort(key=lambda x: x.score, reverse=True)
    
    return merged_hits


def mmr_diversify(hits: List[Evidence], lambda_: float = 0.3, top_k: int = 15) -> List[Evidence]:
    """Apply Maximal Marginal Relevance diversification."""
    if len(hits) <= top_k:
        return hits
    
    selected = []
    remaining = hits.copy()
    
    # Always include the top result
    if remaining:
        selected.append(remaining.pop(0))
    
    while len(selected) < top_k and remaining:
        best_score = -1
        best_idx = 0
        
        for i, candidate in enumerate(remaining):
            relevance = candidate.score
            
            # Diversity penalty
            diversity_penalty = 0
            for selected_hit in selected:
                if candidate.document_id == selected_hit.document_id:
                    diversity_penalty += 0.3
                    if abs(candidate.page - selected_hit.page) <= 1:
                        diversity_penalty += 0.2
            
            mmr_score = lambda_ * relevance - (1 - lambda_) * diversity_penalty
            
            if mmr_score > best_score:
                best_score = mmr_score
                best_idx = i
        
        selected.append(remaining.pop(best_idx))
    
    return selected


def retrieve(q: str, namespaces=("personal",), topk=15) -> List[Evidence]:
    """
    Main retrieval function implementing hybrid search.
    
    1) classify → prefilter (PG)
    2) embed → FAISS (per-namespace)
    3) BM25 (per-namespace)
    4) normalize + interleave → MMR
    5) return Evidence[{doc_id,page,bbox,snippet,score,tlp,namespace}]
    """
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    logger.info(f"Retrieving for query: '{q}' in namespaces: {namespaces}")
    
    # 1. Classify query
    qtype = classify_query(q)
    
    # 2. Prefilter terms
    filters = prefilter_terms(qtype, q, db_url)
    expanded_query = q
    
    # Expand query with aliases/synonyms
    if 'actor_aliases' in filters:
        expanded_query += " " + " ".join(filters['actor_aliases'][:3])
    if 'ttp_synonyms' in filters:
        expanded_query += " " + " ".join(filters['ttp_synonyms'][:3])
    
    all_results = []
    
    for namespace in namespaces:
        faiss_results = []
        bm25_results = []
        
        try:
            # 3. Vector search (FAISS)
            config = get_embedding_config()
            api_key = os.getenv("OPENAI_API_KEY")
            if api_key:
                client = openai.OpenAI(api_key=api_key)
                query_embeddings = generate_embeddings_batch([expanded_query], config, client)
                if query_embeddings:
                    query_vec = np.array(query_embeddings[0], dtype=np.float32)
                    faiss_results = search_faiss(query_vec, topk, namespace)
        except Exception as e:
            logger.warning(f"FAISS search failed: {e}")
        
        try:
            # 4. Keyword search (BM25)
            bm25_results = search_bm25(expanded_query, topk, namespace)
        except Exception as e:
            logger.warning(f"BM25 search failed: {e}")
        
        # 5. Normalize and merge for this namespace
        namespace_results = normalize_and_merge(faiss_results, bm25_results)
        all_results.extend(namespace_results)
    
    # 6. Apply MMR diversification
    all_results.sort(key=lambda x: x.score, reverse=True)
    final_results = mmr_diversify(all_results, lambda_=0.3, top_k=topk)
    
    logger.info(f"Final retrieval results: {len(final_results)} evidence items")
    return final_results
