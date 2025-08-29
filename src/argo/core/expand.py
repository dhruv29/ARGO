"""Deterministic expansions: actor -> aliases/techniques/CVEs; technique -> synonyms; cve -> related techniques."""

import os
import logging
from typing import List, Dict, Any, Optional, Tuple
from dotenv import load_dotenv
import psycopg

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


def get_actor_aliases(actor_name: str, db_url: str = None) -> List[str]:
    """
    Get all aliases for an actor from the database.
    
    Args:
        actor_name: Actor name to look up
        db_url: Database connection URL
    
    Returns:
        List of actor aliases including the original name
    """
    if not db_url:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    aliases = [actor_name]  # Include the original name
    
    try:
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # Look for exact match or partial match in names array
                cur.execute("""
                    SELECT DISTINCT names 
                    FROM actor 
                    WHERE %s = ANY(names) 
                    OR id ILIKE %s 
                    OR %s ILIKE ANY(names)
                    OR EXISTS (
                        SELECT 1 FROM unnest(names) as name 
                        WHERE name ILIKE %s
                    )
                """, (actor_name, f"%{actor_name}%", actor_name, f"%{actor_name}%"))
                
                rows = cur.fetchall()
                
                for row in rows:
                    if row[0]:  # names array
                        aliases.extend(row[0])
                
                # Remove duplicates and empty strings
                aliases = list(set(name.strip() for name in aliases if name and name.strip()))
                
                logger.info(f"Found {len(aliases)} aliases for actor '{actor_name}': {aliases}")
                
    except Exception as e:
        logger.warning(f"Failed to lookup actor aliases for '{actor_name}': {e}")
    
    return aliases


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