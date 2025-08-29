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
    # Enhanced scoring signals
    semantic_score: Optional[float] = None
    lexical_score: Optional[float] = None
    layout_score: Optional[float] = None
    entity_density: Optional[float] = None
    recency_score: Optional[float] = None


def calculate_layout_score(page: int, bbox: List[float], doc_id: str) -> float:
    """Calculate layout-based confidence score."""
    # Higher scores for content near top of page (titles, headers)
    if not bbox or len(bbox) < 4:
        return 0.5
    
    y_position = bbox[1]  # Assuming [x1, y1, x2, y2] format
    
    # Normalize y position (closer to top = higher score)
    # Assume typical page height is 792 points (US Letter)
    normalized_y = min(1.0, max(0.0, (792 - y_position) / 792))
    
    # Boost for first few pages (executive summaries, key findings)
    page_boost = 1.0
    if page <= 3:
        page_boost = 1.2
    elif page <= 10:
        page_boost = 1.1
    
    return min(1.0, normalized_y * page_boost)


def calculate_entity_density(text: str, query: str) -> float:
    """Calculate density of CTI entities in text."""
    text_lower = text.lower()
    query_lower = query.lower()
    
    # Count various CTI indicators
    indicators = [
        r'\bcve-\d{4}-\d{4,}\b',  # CVEs
        r'\bt\d{4}(\.\d{3})?\b',   # ATT&CK techniques
        r'\bapt\d+\b',             # APT groups
        r'\bfin\d+\b',             # FIN groups
        r'\b(malware|trojan|backdoor|ransomware|payload)\b',  # Malware types
        r'\b(c2|command.and.control|exfiltration|persistence)\b',  # TTP keywords
        r'\b(vulnerability|exploit|zero.day|0day)\b',  # Vuln keywords
        r'\b(campaign|operation|actor|threat.group)\b'  # Actor keywords
    ]
    
    total_matches = 0
    for pattern in indicators:
        matches = len(re.findall(pattern, text_lower))
        total_matches += matches
    
    # Query term density
    query_matches = text_lower.count(query_lower)
    
    # Normalize by text length
    text_words = len(text.split())
    if text_words == 0:
        return 0.0
    
    density = (total_matches + query_matches * 2) / text_words
    return min(1.0, density * 10)  # Scale up and cap at 1.0


def calculate_recency_score(doc_id: str, db_url: str) -> float:
    """Calculate recency score based on document creation/ingestion date."""
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT created_at FROM document WHERE id = %s
                """, (doc_id,))
                
                row = cur.fetchone()
                if not row:
                    return 0.5
                
                from datetime import datetime, timezone
                doc_date = row[0]
                now = datetime.now(timezone.utc)
                
                # Score based on age (fresher = higher score)
                age_days = (now - doc_date).days
                if age_days <= 30:
                    return 1.0
                elif age_days <= 90:
                    return 0.8
                elif age_days <= 365:
                    return 0.6
                else:
                    return 0.4
    except Exception:
        return 0.5


def retrieve_counter_evidence(query: str, primary_evidence: List[Evidence], db_url: str, top_k: int = 5) -> List[Evidence]:
    """
    Retrieve counter-evidence to reduce confirmation bias.
    
    Args:
        query: Original search query
        primary_evidence: Primary evidence results
        db_url: Database connection URL
        top_k: Number of counter-evidence items to retrieve
    
    Returns:
        List of counter-evidence items
    """
    if not primary_evidence:
        return []
    
    # Extract key terms from primary evidence for contradiction detection
    primary_terms = set()
    for ev in primary_evidence:
        if hasattr(ev, 'actors') and ev.actors:
            primary_terms.update(ev.actors)
        if hasattr(ev, 'techniques') and ev.techniques:
            primary_terms.update(ev.techniques)
        if hasattr(ev, 'cves') and ev.cves:
            primary_terms.update(ev.cves)
    
    # Generate counter-queries
    counter_queries = []
    
    # 1. Negation queries
    for term in list(primary_terms)[:3]:  # Limit to avoid too many queries
        counter_queries.append(f"NOT {term}")
        counter_queries.append(f"different from {term}")
    
    # 2. Contradiction patterns
    contradiction_patterns = [
        "false positive",
        "misattribution", 
        "different actor",
        "unrelated",
        "no evidence",
        "disputed",
        "debunked"
    ]
    
    for pattern in contradiction_patterns:
        counter_queries.append(f"{pattern} {query}")
    
    # 3. Temporal contradictions (different time periods)
    temporal_queries = [
        f"{query} before 2020",
        f"{query} after 2025",
        f"{query} timeline conflict"
    ]
    counter_queries.extend(temporal_queries)
    
    # Retrieve counter-evidence using modified queries
    counter_evidence = []
    
    try:
        for counter_query in counter_queries[:5]:  # Limit queries to avoid API costs
            # Use BM25 for counter-evidence (more focused on keywords)
            results = search_bm25(counter_query, top_k=3, namespace="personal")
            
            for result in results:
                # Check if this is actually counter-evidence
                if _is_counter_evidence(result, primary_evidence, query):
                    result.confidence *= 0.8  # Slightly reduce confidence for counter-evidence
                    counter_evidence.append(result)
                    
                    if len(counter_evidence) >= top_k:
                        break
            
            if len(counter_evidence) >= top_k:
                break
                
    except Exception as e:
        logger.warning(f"Failed to retrieve counter-evidence: {e}")
    
    # Remove duplicates and limit results
    seen_chunks = set()
    unique_counter_evidence = []
    
    for ev in counter_evidence:
        if ev.chunk_id not in seen_chunks:
            seen_chunks.add(ev.chunk_id)
            unique_counter_evidence.append(ev)
            
            if len(unique_counter_evidence) >= top_k:
                break
    
    logger.info(f"Retrieved {len(unique_counter_evidence)} counter-evidence items for query: {query}")
    return unique_counter_evidence


def _is_counter_evidence(evidence: Evidence, primary_evidence: List[Evidence], query: str) -> bool:
    """
    Determine if evidence item is actually counter-evidence.
    
    Args:
        evidence: Evidence item to evaluate
        primary_evidence: Primary evidence results
        query: Original search query
    
    Returns:
        True if this is counter-evidence
    """
    text = evidence.snippet.lower()
    
    # Check for explicit contradiction indicators
    contradiction_indicators = [
        'not', 'no', 'false', 'incorrect', 'wrong', 'misleading',
        'different', 'unrelated', 'no evidence', 'disputed',
        'debunked', 'retracted', 'correction', 'clarification'
    ]
    
    has_contradiction_indicators = any(indicator in text for indicator in contradiction_indicators)
    
    # Check for temporal conflicts
    temporal_conflicts = [
        'before', 'after', 'earlier', 'later', 'timeline',
        'date', 'period', 'era', 'decade'
    ]
    
    has_temporal_conflicts = any(conflict in text for conflict in temporal_conflicts)
    
    # Check for actor misattribution
    actor_misattribution = [
        'mistaken', 'misidentified', 'wrong actor', 'different group',
        'attributed to', 'blamed on', 'accused of'
    ]
    
    has_actor_misattribution = any(term in text for term in actor_misattribution)
    
    # Must have at least one counter-indicator
    return has_contradiction_indicators or has_temporal_conflicts or has_actor_misattribution


def calculate_composite_confidence(evidence: Evidence, query: str, db_url: str) -> float:
    """Calculate composite confidence score from multiple signals."""
    scores = []
    weights = []
    
    # Semantic similarity (if from FAISS)
    if evidence.source == "faiss" and evidence.semantic_score is not None:
        scores.append(evidence.semantic_score)
        weights.append(0.3)
    
    # Lexical matching (if from BM25)
    if evidence.source == "bm25" and evidence.lexical_score is not None:
        scores.append(evidence.lexical_score)
        weights.append(0.25)
    
    # Layout position
    layout_score = calculate_layout_score(evidence.page, evidence.bbox, evidence.document_id)
    scores.append(layout_score)
    weights.append(0.15)
    
    # Entity density
    entity_score = calculate_entity_density(evidence.snippet, query)
    scores.append(entity_score)
    weights.append(0.2)
    
    # Recency
    recency_score = calculate_recency_score(evidence.document_id, db_url)
    scores.append(recency_score)
    weights.append(0.1)
    
    # Weighted average
    if not scores:
        return 0.5
    
    weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
    total_weight = sum(weights)
    
    return weighted_sum / total_weight if total_weight > 0 else 0.5


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
            cves=cves or [],
            semantic_score=float(score)  # Store original FAISS score
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
            cves=chunk['cves'],
            lexical_score=float(scores[idx])  # Store original BM25 score
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
    
    # 6. Calculate composite confidence scores
    for evidence in all_results:
        composite_confidence = calculate_composite_confidence(evidence, q, db_url)
        evidence.confidence = composite_confidence
        # Update main score to be composite confidence for ranking
        evidence.score = composite_confidence
    
    # 7. Retrieve counter-evidence to reduce confirmation bias
    counter_evidence = retrieve_counter_evidence(q, all_results, db_url, top_k=min(3, topk//3))
    
    # 8. Apply MMR diversification to primary evidence
    all_results.sort(key=lambda x: x.score, reverse=True)
    final_results = mmr_diversify(all_results, lambda_=0.3, top_k=topk)
    
    # 9. Add counter-evidence at the end (marked as such)
    for ev in counter_evidence:
        ev.source = "counter_evidence"
        ev.score *= 0.7  # Reduce score for counter-evidence in ranking
        final_results.append(ev)
    
    logger.info(f"Final retrieval results: {len(final_results)} evidence items (including {len(counter_evidence)} counter-evidence)")
    return final_results
