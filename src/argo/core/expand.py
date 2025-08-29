"""Deterministic expansions: actor -> aliases/techniques/CVEs; technique -> synonyms; cve -> related techniques."""

import os
import logging
import json
import re
from typing import List, Dict, Any, Optional, Tuple, Set
from dotenv import load_dotenv
import psycopg

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def canonicalize_alias(alias: str) -> str:
    """
    Canonicalize alias to standard form.
    
    Args:
        alias: Raw alias string
    
    Returns:
        Canonicalized alias string
    """
    if not alias:
        return ""
    
    # Convert to lowercase for normalization
    canonical = alias.lower().strip()
    
    # Remove common prefixes/suffixes
    prefixes_to_remove = ['apt', 'fin', 'group', 'team', 'actor', 'threat']
    suffixes_to_remove = ['group', 'team', 'actor', 'threat', 'campaign']
    
    for prefix in prefixes_to_remove:
        if canonical.startswith(prefix + ' '):
            canonical = canonical[len(prefix + ' '):]
    
    for suffix in suffixes_to_remove:
        if canonical.endswith(' ' + suffix):
            canonical = canonical[:-len(' ' + suffix)]
    
    # Normalize common variations
    variations = {
        'cozy bear': 'cozybear',
        'fancy bear': 'fancybear',
        'voodoo bear': 'voodoobear',
        'hidden cobra': 'hiddencobra',
        'wizard spider': 'wizardspider',
        'trickbot': 'trickbot',
        'ryuk': 'ryuk'
    }
    
    canonical = variations.get(canonical, canonical)
    
    # Remove extra whitespace and normalize
    canonical = re.sub(r'\s+', ' ', canonical).strip()
    
    return canonical


def cluster_aliases(aliases: List[str]) -> Dict[str, List[str]]:
    """
    Cluster aliases by canonical form to identify duplicates.
    
    Args:
        aliases: List of raw aliases
    
    Returns:
        Dict mapping canonical forms to lists of original aliases
    """
    clusters = {}
    
    for alias in aliases:
        if not alias or not alias.strip():
            continue
            
        canonical = canonicalize_alias(alias)
        if canonical not in clusters:
            clusters[canonical] = []
        clusters[canonical].append(alias)
    
    return clusters


def disambiguate_aliases(aliases: List[str], db_url: str = None) -> Tuple[List[str], Dict[str, Any]]:
    """
    Disambiguate aliases using database context and similarity.
    
    Args:
        aliases: List of aliases to disambiguate
        db_url: Database connection URL
    
    Returns:
        Tuple of (disambiguated_aliases, disambiguation_metadata)
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    # Cluster aliases by canonical form
    clusters = cluster_aliases(aliases)
    
    # Get disambiguation metadata
    metadata = {
        "total_aliases": len(aliases),
        "unique_canonical_forms": len(clusters),
        "clusters": clusters,
        "disambiguation_rules_applied": []
    }
    
    disambiguated = []
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                for canonical, alias_cluster in clusters.items():
                    if len(alias_cluster) == 1:
                        # Single alias in cluster - no disambiguation needed
                        disambiguated.append(alias_cluster[0])
                        continue
                    
                    # Multiple aliases in cluster - need to disambiguate
                    logger.info(f"Disambiguating cluster '{canonical}': {alias_cluster}")
                    
                    # Get confidence scores from database
                    alias_scores = {}
                    for alias in alias_cluster:
                        cur.execute("""
                            SELECT a.confidence, a.source, COUNT(*) as usage_count
                            FROM alias a
                            WHERE a.name ILIKE %s
                            GROUP BY a.confidence, a.source
                        """, (f"%{alias}%",))
                        
                        rows = cur.fetchall()
                        if rows:
                            # Use highest confidence score
                            max_confidence = max(row[0] for row in rows if row[0])
                            source = rows[0][1] if rows[0][1] else 'unknown'
                            usage_count = sum(row[2] for row in rows)
                            
                            alias_scores[alias] = {
                                'confidence': max_confidence,
                                'source': source,
                                'usage_count': usage_count
                            }
                        else:
                            alias_scores[alias] = {
                                'confidence': 0.5,
                                'source': 'unknown',
                                'usage_count': 0
                            }
                    
                    # Apply disambiguation rules
                    best_alias = None
                    best_score = -1
                    rule_applied = None
                    
                    for alias, scores in alias_scores.items():
                        # Rule 1: Prefer deterministic sources over LLM
                        source_multiplier = 1.0
                        if scores['source'] == 'seed':
                            source_multiplier = 1.2
                        elif scores['source'] == 'rag_llm':
                            source_multiplier = 0.9
                        
                        # Rule 2: Prefer higher confidence
                        confidence_score = scores['confidence'] * source_multiplier
                        
                        # Rule 3: Prefer more frequently used aliases
                        usage_bonus = min(0.1, scores['usage_count'] * 0.02)
                        
                        total_score = confidence_score + usage_bonus
                        
                        if total_score > best_score:
                            best_score = total_score
                            best_alias = alias
                            rule_applied = f"source={scores['source']}, confidence={scores['confidence']:.2f}, usage={scores['usage_count']}"
                    
                    if best_alias:
                        disambiguated.append(best_alias)
                        metadata["disambiguation_rules_applied"].append({
                            "cluster": canonical,
                            "selected": best_alias,
                            "alternatives": [a for a in cluster_aliases if a != best_alias],
                            "rule": rule_applied,
                            "score": best_score
                        })
                    else:
                        # Fallback: use first alias
                        disambiguated.append(cluster_aliases[0])
                        metadata["disambiguation_rules_applied"].append({
                            "cluster": canonical,
                            "selected": cluster_aliases[0],
                            "alternatives": cluster_aliases[1:],
                            "rule": "fallback",
                            "score": 0.0
                        })
    
    except Exception as e:
        logger.warning(f"Failed to disambiguate aliases: {e}")
        # Fallback: return original aliases
        disambiguated = aliases
    
    metadata["final_aliases"] = disambiguated
    return disambiguated, metadata


def resolve_actor_aliases(actor_name: str, db_url: str = None) -> List[str]:
    """
    Deterministic-first alias resolution.
    
    1) Query alias table and actor.names
    2) Return unique list
    
    Args:
        actor_name: Actor name to look up
        db_url: Database connection URL
    
    Returns:
        List of actor aliases including the original name
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    aliases = [actor_name]  # Always include the query term
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # 1) Query alias table first (new provenance-tracked table)
                cur.execute("""
                    SELECT DISTINCT a.name, a.source, a.confidence
                    FROM alias a
                    JOIN actor act ON a.actor_id = act.id
                    WHERE a.name ILIKE %s 
                    OR act.id ILIKE %s
                    OR %s = ANY(act.names)
                    ORDER BY a.confidence DESC
                """, (f"%{actor_name}%", f"%{actor_name}%", actor_name))
                
                alias_rows = cur.fetchall()
                
                if alias_rows:
                    # Found in alias table - use these (higher fidelity)
                    for row in alias_rows:
                        if row[0] and row[0].strip():
                            aliases.append(row[0].strip())
                    
                    # Also get all aliases for the same actor_id for completeness
                    cur.execute("""
                        SELECT DISTINCT a.name
                        FROM alias a
                        WHERE a.actor_id IN (
                            SELECT DISTINCT a2.actor_id
                            FROM alias a2
                            JOIN actor act ON a2.actor_id = act.id
                            WHERE a2.name ILIKE %s OR act.id ILIKE %s OR %s = ANY(act.names)
                        )
                        AND a.confidence >= 0.7
                        ORDER BY a.name
                    """, (f"%{actor_name}%", f"%{actor_name}%", actor_name))
                    
                    complete_aliases = cur.fetchall()
                    for row in complete_aliases:
                        if row[0] and row[0].strip():
                            aliases.append(row[0].strip())
                
                else:
                    # Fallback to legacy actor.names array
                    cur.execute("""
                        SELECT DISTINCT names 
                        FROM actor 
                        WHERE %s = ANY(names) 
                        OR id ILIKE %s 
                        OR %s ILIKE ANY(names)
                    """, (actor_name, f"%{actor_name}%", actor_name))
                    
                    rows = cur.fetchall()
                    for row in rows:
                        if row[0]:  # names array
                            aliases.extend(row[0])
                
                # Remove duplicates and empty strings
                aliases = list(set(name.strip() for name in aliases if name and name.strip()))
                
                # Apply alias disambiguation
                if len(aliases) > 1:
                    disambiguated_aliases, disambiguation_metadata = disambiguate_aliases(aliases, db_url)
                    logger.info(f"Disambiguated {len(aliases)} aliases to {len(disambiguated_aliases)} unique forms")
                    logger.debug(f"Disambiguation metadata: {disambiguation_metadata}")
                    aliases = disambiguated_aliases
                
                logger.info(f"Deterministic resolve: Found {len(aliases)} aliases for '{actor_name}': {aliases}")
                
    except Exception as e:
        logger.warning(f"Failed to resolve actor aliases for '{actor_name}': {e}")
    
    return aliases


def get_actor_aliases(actor_name: str, db_url: str = None) -> List[str]:
    """Legacy function - redirects to resolve_actor_aliases for backward compatibility."""
    return resolve_actor_aliases(actor_name, db_url)


def get_actor_techniques(actor_name: str, db_url: str = None) -> List[str]:
    """
    Get techniques associated with an actor.
    
    Args:
        actor_name: Actor name to look up
        db_url: Database connection URL
    
    Returns:
        List of technique IDs (e.g., T1566.001)
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    techniques = []
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # In a real implementation, this would join actor-technique mappings
                # For now, we'll return common techniques as placeholders
                cur.execute("""
                    SELECT t_id, name 
                    FROM technique 
                    WHERE name IS NOT NULL
                    LIMIT 10
                """)
                
                rows = cur.fetchall()
                techniques = [row[0] for row in rows if row[0]]
                
                logger.info(f"Found {len(techniques)} techniques for actor '{actor_name}'")
                
    except Exception as e:
        logger.warning(f"Failed to lookup techniques for actor '{actor_name}': {e}")
    
    return techniques


def get_actor_cves(actor_name: str, db_url: str = None) -> List[str]:
    """
    Get CVEs associated with an actor.
    
    Args:
        actor_name: Actor name to look up  
        db_url: Database connection URL
    
    Returns:
        List of CVE IDs (e.g., CVE-2023-23397)
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    cves = []
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # In a real implementation, this would join actor-CVE mappings  
                # For now, we'll return high-profile CVEs as placeholders
                cur.execute("""
                    SELECT id 
                    FROM cve 
                    WHERE cvss > 7.0 OR kev = true
                    LIMIT 10
                """)
                
                rows = cur.fetchall()
                cves = [row[0] for row in rows if row[0]]
                
                logger.info(f"Found {len(cves)} CVEs for actor '{actor_name}'")
                
    except Exception as e:
        logger.warning(f"Failed to lookup CVEs for actor '{actor_name}': {e}")
    
    return cves


def get_technique_synonyms(technique_id: str, db_url: str = None) -> List[str]:
    """
    Get synonyms for a technique.
    
    Args:
        technique_id: Technique ID (e.g., T1566)
        db_url: Database connection URL
    
    Returns:
        List of technique synonyms
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    synonyms = [technique_id]
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT synonyms, name 
                    FROM technique 
                    WHERE t_id = %s
                """, (technique_id,))
                
                row = cur.fetchone()
                if row:
                    if row[0]:  # synonyms array
                        synonyms.extend(row[0])
                    if row[1]:  # technique name
                        synonyms.append(row[1])
                
                # Remove duplicates
                synonyms = list(set(s.strip() for s in synonyms if s and s.strip()))
                
                logger.info(f"Found {len(synonyms)} synonyms for technique '{technique_id}'")
                
    except Exception as e:
        logger.warning(f"Failed to lookup synonyms for technique '{technique_id}': {e}")
    
    return synonyms


def get_cve_techniques(cve_id: str, db_url: str = None) -> List[str]:
    """
    Get techniques related to a CVE.
    
    Args:
        cve_id: CVE ID (e.g., CVE-2023-23397)
        db_url: Database connection URL
    
    Returns:
        List of related technique IDs
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    techniques = []
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT ct.t_id, t.name
                    FROM cve_technique ct
                    JOIN technique t ON ct.t_id = t.t_id
                    WHERE ct.cve_id = %s
                    ORDER BY ct.weight DESC
                """, (cve_id,))
                
                rows = cur.fetchall()
                techniques = [row[0] for row in rows if row[0]]
                
                logger.info(f"Found {len(techniques)} techniques for CVE '{cve_id}'")
                
    except Exception as e:
        logger.warning(f"Failed to lookup techniques for CVE '{cve_id}': {e}")
    
    return techniques


def expand_actor(actor_name: str, db_url: str = None) -> Dict[str, List[str]]:
    """
    Comprehensive expansion of an actor to all related aliases, techniques, and CVEs.
    
    Args:
        actor_name: Actor name to expand
        db_url: Database connection URL
    
    Returns:
        Dict with 'aliases', 'techniques', and 'cves' keys
    """
    logger.info(f"Expanding actor: {actor_name}")
    
    expansion = {
        'aliases': get_actor_aliases(actor_name, db_url),
        'techniques': get_actor_techniques(actor_name, db_url),
        'cves': get_actor_cves(actor_name, db_url)
    }
    
    total_items = sum(len(v) for v in expansion.values())
    logger.info(f"Actor expansion complete: {total_items} total items")
    
    return expansion


def _extract_aliases_with_rag_llm(
    actor: str, 
    evidence: List[Dict[str, Any]], 
    db_url: str = None
) -> List[Dict[str, Any]]:
    """
    Use only provided evidence chunks (RAG) to run an extract-only LLM prompt.
    
    Args:
        actor: Actor name to find aliases for
        evidence: List of evidence items from retrieval
        db_url: Database connection URL
    
    Returns:
        List of dicts: {alias, doc_id, page, snippet, confidence, model}
    """
    import openai
    import json
    import hashlib
    from tenacity import retry, stop_after_attempt, wait_exponential
    
    if not evidence:
        return []
    
    # Build evidence context
    evidence_text = ""
    for i, item in enumerate(evidence[:10]):  # Limit to top 10 chunks
        snippet = item.get('snippet', item.get('text', ''))
        doc_id = item.get('document_id', 'unknown')
        page = item.get('page', 'unknown')
        evidence_text += f"[Doc {doc_id}, Page {page}]: {snippet}\n\n"
    
    # Extract-only prompt with JSON schema
    system_prompt = """
You are a cyberthreat intelligence analyst. Extract ONLY actor aliases/names from the provided evidence.

Rules:
1. ONLY extract names that clearly refer to the same threat actor
2. Include confidence score 0.0-1.0 based on evidence strength
3. Return valid JSON only, no other text
4. If no aliases found, return empty array

JSON Schema:
[
  {
    "alias": "string (the alias/name found)",
    "confidence": float (0.0-1.0),
    "evidence_snippet": "string (the specific text that mentions this alias)"
  }
]"""
    
    user_prompt = f"""Extract aliases for threat actor: {actor}

Evidence:
{evidence_text}

Return JSON array of aliases found:"""
    
    try:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning("No OpenAI API key for LLM fallback")
            return []
        
        model = os.getenv("FALLBACK_RAG_LLM_MODEL", "gpt-4o-mini")
        max_tokens = int(os.getenv("FALLBACK_RAG_LLM_MAX_TOKENS", "800"))
        
        client = openai.OpenAI(api_key=api_key)
        
        @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=4))
        def _call_llm():
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=max_tokens
            )
            return response.choices[0].message.content
        
        response_text = _call_llm()
        
        # Parse JSON response
        try:
            aliases_data = json.loads(response_text)
            if not isinstance(aliases_data, list):
                logger.warning(f"LLM returned non-list: {type(aliases_data)}")
                return []
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM JSON response: {e}")
            return []
        
        # Convert to our format and add metadata
        candidates = []
        for item in aliases_data:
            if not isinstance(item, dict) or 'alias' not in item:
                continue
            
            alias = item.get('alias', '').strip()
            confidence = float(item.get('confidence', 0.0))
            snippet = item.get('evidence_snippet', '')[:200]
            
            if not alias or confidence < 0.1:
                continue
            
            # Find best matching evidence item for metadata
            best_evidence = evidence[0]  # Default to first
            for ev in evidence:
                if snippet.lower() in ev.get('snippet', '').lower():
                    best_evidence = ev
                    break
            
            candidate = {
                'alias': alias,
                'doc_id': best_evidence.get('document_id', 'unknown'),
                'page': best_evidence.get('page', 0),
                'snippet': snippet,
                'confidence': min(confidence, 1.0),  # Clamp to 1.0
                'model': model,
                'snippet_hash': hashlib.md5(snippet.encode()).hexdigest()[:8]
            }
            
            candidates.append(candidate)
        
        logger.info(f"LLM extracted {len(candidates)} alias candidates for {actor}")
        return candidates
        
    except Exception as e:
        logger.error(f"LLM alias extraction failed: {e}")
        return []


def fallback_aliases(
    actor: str, 
    retrieve_fn, 
    db_url: str = None
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    If no aliases in PG, use retrieval over local corpus + LLM extraction.
    
    Args:
        actor: Actor name to find aliases for
        retrieve_fn: Function to retrieve evidence chunks
        db_url: Database connection URL
    
    Returns:
        Tuple of (aliases, raw_candidates)
    """
    if os.getenv("FALLBACK_RAG_LLM_ENABLED", "false").lower() != "true":
        logger.info("RAG-LLM fallback disabled")
        return [], []
    
    logger.info(f"Running RAG-LLM fallback for actor: {actor}")
    
    try:
        # 1) Get chunks mentioning the actor name
        evidence = retrieve_fn(query=actor, topk=15)
        
        # Convert Evidence objects to dicts if needed
        evidence_dicts = []
        for ev in evidence:
            if hasattr(ev, '__dict__'):
                # Evidence object
                evidence_dicts.append({
                    'document_id': ev.document_id,
                    'page': ev.page,
                    'snippet': ev.snippet,
                    'score': ev.score
                })
            else:
                # Already a dict
                evidence_dicts.append(ev)
        
        if not evidence_dicts:
            logger.info(f"No evidence found for {actor} in local corpus")
            return [], []
        
        # 2) LLM extract-only
        candidates = _extract_aliases_with_rag_llm(actor, evidence_dicts, db_url)
        
        # 3) Apply confidence threshold
        min_conf = float(os.getenv("FALLBACK_ALIAS_CONF_MIN", "0.65"))
        filtered_candidates = [c for c in candidates if c.get('confidence', 0) >= min_conf]
        
        # 4) Extract just the alias names
        aliases = sorted({c['alias'] for c in filtered_candidates})
        
        logger.info(f"RAG-LLM fallback found {len(aliases)} aliases above {min_conf} confidence")
        return list(aliases), candidates
        
    except Exception as e:
        logger.error(f"Fallback alias extraction failed: {e}")
        return [], []


def upsert_aliases(
    actor_id: str, 
    aliases: List[Dict[str, Any]], 
    approved: bool,
    db_url: str = None
) -> None:
    """
    Write to alias table only if approved.
    
    Args:
        actor_id: Actor ID to associate aliases with
        aliases: List of alias candidate dicts
        approved: Whether the write was approved
        db_url: Database connection URL
    """
    if not approved or not aliases:
        logger.info("Alias upsert skipped (not approved or no aliases)")
        return
    
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    try:
        import uuid
        run_id = str(uuid.uuid4())[:8]
        
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                for alias_data in aliases:
                    alias_name = alias_data.get('alias', '').strip()
                    confidence = alias_data.get('confidence', 0.0)
                    
                    if not alias_name:
                        continue
                    
                    # Build provenance JSON
                    provenance = {
                        'doc_id': alias_data.get('doc_id'),
                        'page': alias_data.get('page'),
                        'snippet_hash': alias_data.get('snippet_hash'),
                        'model': alias_data.get('model'),
                        'run_id': run_id,
                        'original_snippet': alias_data.get('snippet', '')[:100]
                    }
                    
                    cur.execute("""
                        INSERT INTO alias (actor_id, name, source, provenance, confidence)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (actor_id, name) DO UPDATE SET
                            confidence = GREATEST(EXCLUDED.confidence, alias.confidence),
                            provenance = EXCLUDED.provenance
                    """, (
                        actor_id,
                        alias_name,
                        'rag_llm',
                        json.dumps(provenance),
                        confidence
                    ))
                
                conn.commit()
                logger.info(f"Upserted {len(aliases)} aliases for actor {actor_id}")
                
    except Exception as e:
        logger.error(f"Failed to upsert aliases: {e}")


def expand_search_terms(terms: List[str], db_url: str = None) -> List[str]:
    """
    Expand a list of search terms with synonyms and related terms.
    
    Args:
        terms: List of terms to expand
        db_url: Database connection URL
    
    Returns:
        Expanded list of search terms
    """
    expanded = set(terms)  # Start with original terms
    
    for term in terms:
        # Check if it looks like a technique ID
        if term.upper().startswith('T') and any(c.isdigit() for c in term):
            expanded.update(get_technique_synonyms(term.upper(), db_url))
        
        # Check if it looks like a CVE
        elif term.upper().startswith('CVE-'):
            expanded.update(get_cve_techniques(term.upper(), db_url))
    
    result = list(expanded)
    logger.info(f"Expanded {len(terms)} terms to {len(result)} terms")
    
    return result


# Seed data functions for testing
def seed_test_actor_data(db_url: str = None) -> None:
    """Seed some test actor data for demonstration."""
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    test_actors = [
        {
            'id': 'fin7',
            'mitre_gid': 'G0046',
            'names': ['FIN7', 'Carbanak Group', 'Navigator Group', 'Sangria Tempest']
        },
        {
            'id': 'apt29',
            'mitre_gid': 'G0016', 
            'names': ['APT29', 'Cozy Bear', 'The Dukes', 'Midnight Blizzard']
        },
        {
            'id': 'apt28',
            'mitre_gid': 'G0007',
            'names': ['APT28', 'Fancy Bear', 'Sofacy', 'Forest Blizzard']
        }
    ]
    
    test_techniques = [
        {'t_id': 'T1566.001', 'name': 'Spearphishing Attachment', 'synonyms': ['phishing', 'malicious email']},
        {'t_id': 'T1055', 'name': 'Process Injection', 'synonyms': ['code injection', 'dll injection']},
        {'t_id': 'T1083', 'name': 'File and Directory Discovery', 'synonyms': ['file enumeration']},
        {'t_id': 'T1059.001', 'name': 'PowerShell', 'synonyms': ['powershell.exe', 'ps1 scripts']},
        {'t_id': 'T1082', 'name': 'System Information Discovery', 'synonyms': ['system recon']}
    ]
    
    test_cves = [
        {'id': 'CVE-2023-23397', 'cvss': 9.8, 'kev': True},
        {'id': 'CVE-2021-34527', 'cvss': 8.8, 'kev': True},
        {'id': 'CVE-2020-1472', 'cvss': 10.0, 'kev': True}
    ]
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # Insert actors
                for actor in test_actors:
                    cur.execute("""
                        INSERT INTO actor (id, mitre_gid, names) 
                        VALUES (%s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            mitre_gid = EXCLUDED.mitre_gid,
                            names = EXCLUDED.names
                    """, (actor['id'], actor['mitre_gid'], actor['names']))
                
                # Insert techniques
                for tech in test_techniques:
                    cur.execute("""
                        INSERT INTO technique (t_id, name, synonyms)
                        VALUES (%s, %s, %s)  
                        ON CONFLICT (t_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            synonyms = EXCLUDED.synonyms
                    """, (tech['t_id'], tech['name'], tech['synonyms']))
                
                # Insert CVEs
                for cve in test_cves:
                    cur.execute("""
                        INSERT INTO cve (id, cvss, kev)
                        VALUES (%s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            cvss = EXCLUDED.cvss,
                            kev = EXCLUDED.kev
                    """, (cve['id'], cve['cvss'], cve['kev']))
            
            conn.commit()
            logger.info("Seeded test actor/technique/CVE data")
            
    except Exception as e:
        logger.error(f"Failed to seed test data: {e}")
        raise