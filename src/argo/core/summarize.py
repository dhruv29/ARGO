


"""Summarization strictly from provided evidence snippets; no uncited claims."""

import os
import logging
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv
import openai
from tenacity import retry, stop_after_attempt, wait_exponential

# Load environment variables  
load_dotenv()

logger = logging.getLogger(__name__)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def generate_summary_with_citations(
    actor: str,
    evidence: List[Dict[str, Any]], 
    report_type: str = "threat_profile"
) -> str:
    """
    Generate a markdown summary from evidence with strict citation requirements.
    
    Args:
        actor: Actor name being profiled
        evidence: List of evidence items with text and metadata
        report_type: Type of report to generate
    
    Returns:
        Markdown report with citations
    """
    if not evidence:
        return f"# Orpheus Profile: {actor}\n\n**No evidence found for this actor.**"
    
    # Prepare evidence context for the LLM
    evidence_context = ""
    for i, item in enumerate(evidence, 1):
        doc_id = item.get('document_id', 'unknown')
        page = item.get('page', 'unknown')
        snippet = item.get('snippet', item.get('text', ''))
        score = item.get('score', 0.0)
        source = item.get('source', 'unknown')
        
        evidence_context += f"\n[Evidence {i}] (Doc: {doc_id}, Page: {page}, Score: {score:.3f}, Source: {source})\n"
        evidence_context += f"{snippet}\n"
    
    # System prompt for strict citation
    system_prompt = """You are Orpheus, a cyberthreat intelligence analyst. Generate a comprehensive threat actor profile based ONLY on the provided evidence snippets.

CRITICAL REQUIREMENTS:
1. NEVER make claims without citing specific evidence
2. Every factual statement must reference [Evidence X] 
3. If evidence is insufficient for a claim, state "Evidence insufficient for..."
4. Use professional CTI language and structure
5. Include confidence levels based on evidence quality
6. Organize into logical sections: Overview, TTPs, Infrastructure, etc.

Format citations as: [Evidence X] where X is the evidence number.
Use markdown formatting with proper headers and bullet points."""

    user_prompt = f"""Generate a threat profile for actor: {actor}

Available Evidence:
{evidence_context}

Generate a professional CTI report with strict citations. Every claim must reference specific evidence."""

    try:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not found")
        
        client = openai.OpenAI(api_key=api_key)
        
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3,  # Lower temperature for more consistent output
            max_tokens=2000
        )
        
        summary = response.choices[0].message.content
        logger.info(f"Generated summary for {actor} with {len(evidence)} evidence items")
        
        return summary
        
    except Exception as e:
        logger.error(f"Failed to generate summary: {e}")
        # Fallback to template-based summary
        return generate_fallback_summary(actor, evidence)


def generate_fallback_summary(actor: str, evidence: List[Dict[str, Any]]) -> str:
    """Generate a simple template-based summary if LLM fails."""
    
    summary = f"# Orpheus Profile: {actor}\n\n"
    summary += f"**Generated from {len(evidence)} evidence items**\n\n"
    
    summary += "## Evidence Summary\n\n"
    
    # Group evidence by document
    doc_groups = {}
    for item in evidence:
        doc_id = item.get('document_id', 'unknown')
        if doc_id not in doc_groups:
            doc_groups[doc_id] = []
        doc_groups[doc_id].append(item)
    
    for doc_id, items in doc_groups.items():
        summary += f"### Document: {doc_id}\n\n"
        for i, item in enumerate(items, 1):
            page = item.get('page', 'unknown')
            snippet = item.get('snippet', item.get('text', ''))[:200]
            score = item.get('score', 0.0)
            source = item.get('source', 'unknown')
            
            summary += f"**Evidence {i}** (Page {page}, Score: {score:.3f}, Source: {source})\n"
            summary += f"> {snippet}...\n\n"
    
    summary += "\n## Analysis Notes\n\n"
    summary += "- This is a fallback summary generated from evidence snippets\n"
    summary += "- Full analysis requires manual review of evidence items\n"
    summary += f"- {len(evidence)} evidence items available for detailed analysis\n"
    
    return summary


def extract_key_indicators(evidence: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Extract key indicators from evidence text."""
    indicators = {
        'ttps': [],
        'cves': [],
        'iocs': [],
        'tools': []
    }
    
    # Simple regex patterns for indicator extraction
    import re
    
    for item in evidence:
        text = item.get('snippet', item.get('text', '')).lower()
        
        # Look for technique IDs
        ttps = re.findall(r't\d{4}(?:\.\d{3})?', text)
        indicators['ttps'].extend(ttps)
        
        # Look for CVEs
        cves = re.findall(r'cve-\d{4}-\d{4,}', text)
        indicators['cves'].extend(cves)
        
        # Look for common tools (basic list)
        tools = ['powershell', 'cmd', 'rundll32', 'regsvr32', 'mshta', 'wmic']
        for tool in tools:
            if tool in text:
                indicators['tools'].append(tool)
    
    # Remove duplicates
    for key in indicators:
        indicators[key] = list(set(indicators[key]))
    
    return indicators


def generate_executive_summary(actor: str, evidence: List[Dict[str, Any]]) -> str:
    """Generate a brief executive summary."""
    
    if not evidence:
        return f"No evidence available for threat actor {actor}."
    
    indicators = extract_key_indicators(evidence)
    
    summary = f"**{actor} Threat Profile Summary**\n\n"
    summary += f"- Evidence Sources: {len(evidence)} items across {len(set(e.get('document_id') for e in evidence))} documents\n"
    
    if indicators['ttps']:
        summary += f"- Techniques: {len(indicators['ttps'])} identified ({', '.join(indicators['ttps'][:3])}...)\n"
    
    if indicators['cves']:
        summary += f"- CVEs: {len(indicators['cves'])} identified ({', '.join(indicators['cves'][:3])}...)\n"
        
    if indicators['tools']:
        summary += f"- Tools: {', '.join(indicators['tools'][:5])}\n"
    
    # Evidence quality assessment
    high_confidence = len([e for e in evidence if e.get('score', 0) > 0.8])
    summary += f"- High Confidence Evidence: {high_confidence}/{len(evidence)} items\n"
    
    return summary


def validate_citations(report: str, evidence_count: int) -> Dict[str, Any]:
    """Validate that all claims in the report have proper citations."""
    import re
    
    # Find all citation references
    citations = re.findall(r'\[Evidence (\d+)\]', report)
    cited_numbers = [int(c) for c in citations]
    
    validation = {
        'total_citations': len(citations),
        'unique_citations': len(set(cited_numbers)),
        'valid_citations': len([c for c in cited_numbers if 1 <= c <= evidence_count]),
        'invalid_citations': [c for c in cited_numbers if c < 1 or c > evidence_count],
        'uncited_evidence': [i for i in range(1, evidence_count + 1) if i not in cited_numbers],
        'citation_coverage': len(set(cited_numbers)) / evidence_count if evidence_count > 0 else 0
    }
    
    return validation


def create_evidence_pack(evidence: List[Dict[str, Any]], actor: str) -> List[Dict[str, Any]]:
    """Create a structured evidence pack for export."""
    
    evidence_pack = []
    
    for i, item in enumerate(evidence, 1):
        evidence_item = {
            'evidence_id': i,
            'actor': actor,
            'document_id': item.get('document_id'),
            'page': item.get('page'),
            'chunk_id': item.get('chunk_id'),
            'bbox': item.get('bbox', []),
            'snippet': item.get('snippet', item.get('text', '')),
            'score': item.get('score', 0.0),
            'confidence': item.get('confidence', 1.0),
            'source': item.get('source', 'unknown'),
            'tlp': item.get('tlp', 'CLEAR'),
            'namespace': item.get('namespace', 'personal'),
            'actors': item.get('actors', []),
            'techniques': item.get('techniques', []),
            'cves': item.get('cves', []),
            'timestamp': item.get('timestamp')
        }
        
        evidence_pack.append(evidence_item)
    
    logger.info(f"Created evidence pack with {len(evidence_pack)} items for {actor}")
    return evidence_pack