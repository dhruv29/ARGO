import os
import logging
from typing import TypedDict, Literal, Optional, Dict, Any, List
from pathlib import Path
from langgraph.graph import StateGraph, END
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)

# ---- State definition (keep small & explicit)
class OrpheusState(TypedDict, total=False):
    run_id: str
    actor: str
    plan: Dict[str, Any]           # search plan (filters, namespaces, etc.)
    aliases: List[str]
    ttps: List[str]
    cves: List[str]
    evidence: List[Dict[str, Any]] # evidence items (doc_id,page,bbox,snippet,score)
    draft_report: str              # markdown draft (pre-approval)
    approved: bool
    outputs: Dict[str, str]        # paths to report / jsonl
    # Additional fields for enhanced functionality
    alias_candidates: List[Dict[str, Any]]  # RAG-LLM discovered aliases
    needs_alias_write_approval: bool        # Whether alias approval is needed
    approved_alias_write: bool              # Whether alias write was approved
    audit_logger: Any                       # Audit logger instance

# ---- Step functions (call into your core modules; stubbed now)
def step_resolve(state: OrpheusState) -> OrpheusState:
    """Deterministic-first actor resolution with guarded LLM fallback."""
    from ..core.expand import resolve_actor_aliases, fallback_aliases
    from ..core.retrieve import retrieve
    
    actor = state.get("actor", "").strip()
    logger.info(f"Resolving actor: {actor}")
    
    # Initialize plan
    state["plan"] = {
        "router": "hybrid",
        "namespaces": ["personal"],
        "search_terms": [actor]
    }
    
    # 1) Deterministic PG lookup first
    aliases = resolve_actor_aliases(actor)
    
    if len(aliases) > 1:  # Found deterministic aliases
        state["aliases"] = aliases
        state["plan"]["search_terms"] = [actor] + aliases[:3]  # Limit expansion
        logger.info(f"Deterministic resolve: {actor} -> {len(aliases)} aliases")
        return state
    
    # 2) Fallback path - RAG-LLM extraction
    logger.info(f"No deterministic aliases for {actor}, trying RAG-LLM fallback")
    
    def retrieve_fn(query, topk=15):
        """Wrapper for retrieve function."""
        try:
            return retrieve(query, namespaces=("personal",), topk=topk)
        except Exception as e:
            logger.warning(f"Retrieve failed in fallback: {e}")
            return []
    
    fallback_aliases_list, alias_candidates = fallback_aliases(actor, retrieve_fn)
    
    if fallback_aliases_list:
        state["aliases"] = [actor] + fallback_aliases_list
        state["alias_candidates"] = alias_candidates
        state["needs_alias_write_approval"] = True
        state["plan"]["search_terms"] = [actor] + fallback_aliases_list[:3]
        logger.info(f"RAG-LLM fallback: {actor} -> {len(fallback_aliases_list)} candidate aliases")
    else:
        state["aliases"] = [actor]  # Just the original actor name
        logger.info(f"No aliases found for {actor} (deterministic or fallback)")
    
    return state

def step_expand(state: OrpheusState) -> OrpheusState:
    """Expand -> ttps, cves using PG joins."""
    from ..core.expand import get_actor_techniques, get_actor_cves, expand_search_terms
    
    actor = state.get("actor", "")
    aliases = state.get("aliases", [])
    
    logger.info(f"Expanding actor {actor} to TTPs and CVEs")
    
    # Get techniques and CVEs for the actor
    ttps = get_actor_techniques(actor)
    cves = get_actor_cves(actor)
    
    state["ttps"] = ttps
    state["cves"] = cves
    
    # Expand search terms to include techniques and CVEs
    search_terms = state["plan"].get("search_terms", [])
    expanded_terms = expand_search_terms(search_terms + ttps + cves)
    
    state["plan"]["search_terms"] = expanded_terms[:10]  # Limit to avoid over-expansion
    
    logger.info(f"Expanded to {len(ttps)} TTPs and {len(cves)} CVEs")
    return state

def step_retrieve(state: OrpheusState) -> OrpheusState:
    """Call core.retrieve.retrieve() with plan; return top-k evidence."""
    from ..core.retrieve import retrieve
    
    actor = state.get("actor", "")
    plan = state.get("plan", {})
    search_terms = plan.get("search_terms", [actor])
    namespaces = plan.get("namespaces", ["personal"])
    
    logger.info(f"Retrieving evidence for {actor} using {len(search_terms)} search terms")
    
    all_evidence = []
    
    # Search for each term and collect evidence
    for term in search_terms[:5]:  # Limit to top 5 terms to avoid too many queries
        try:
            results = retrieve(term, namespaces=tuple(namespaces), topk=10)
            
            # Convert Evidence objects to dicts for state storage
            for evidence in results:
                evidence_dict = {
                    'chunk_id': evidence.chunk_id,
                    'document_id': evidence.document_id,
                    'page': evidence.page,
                    'bbox': evidence.bbox,
                    'snippet': evidence.snippet,
                    'score': evidence.score,
                    'confidence': evidence.confidence,
                    'tlp': evidence.tlp,
                    'namespace': evidence.namespace,
                    'source': evidence.source,
                    'actors': evidence.actors or [],
                    'techniques': evidence.techniques or [],
                    'cves': evidence.cves or [],
                    'search_term': term
                }
                all_evidence.append(evidence_dict)
        
        except Exception as e:
            logger.warning(f"Failed to retrieve evidence for term '{term}': {e}")
    
    # Remove duplicates based on chunk_id and sort by score
    seen_chunks = set()
    unique_evidence = []
    
    for evidence in sorted(all_evidence, key=lambda x: x['score'], reverse=True):
        if evidence['chunk_id'] not in seen_chunks:
            seen_chunks.add(evidence['chunk_id'])
            unique_evidence.append(evidence)
    
    # Limit to top evidence items
    state["evidence"] = unique_evidence[:20]
    
    logger.info(f"Retrieved {len(state['evidence'])} unique evidence items for {actor}")
    return state

def step_summarize(state: OrpheusState) -> OrpheusState:
    """Call core.summarize to produce markdown strictly from evidence."""
    from ..core.summarize import generate_summary_with_citations, validate_citations
    
    actor = state.get("actor", "(unknown)")
    evidence = state.get("evidence", [])
    
    logger.info(f"Generating summary for {actor} from {len(evidence)} evidence items")
    
    if not evidence:
        state["draft_report"] = f"# Orpheus Profile: {actor}\n\n**No evidence found for this actor.**"
        return state
    
    try:
        # Generate the summary with citations
        draft_report = generate_summary_with_citations(actor, evidence)
        
        # Validate citations
        validation = validate_citations(draft_report, len(evidence))
        
        # Add validation summary to the report
        validation_summary = f"\n\n---\n\n## Citation Analysis\n\n"
        validation_summary += f"- Total Citations: {validation['total_citations']}\n"
        validation_summary += f"- Evidence Coverage: {validation['citation_coverage']:.1%}\n"
        validation_summary += f"- Valid Citations: {validation['valid_citations']}/{validation['total_citations']}\n"
        
        if validation['invalid_citations']:
            validation_summary += f"- Invalid Citations: {validation['invalid_citations']}\n"
        
        draft_report += validation_summary
        
        state["draft_report"] = draft_report
        
        logger.info(f"Generated summary with {validation['total_citations']} citations")
        
    except Exception as e:
        logger.error(f"Failed to generate summary: {e}")
        state["draft_report"] = f"# Orpheus Profile: {actor}\n\n**Error generating summary:** {str(e)}"
    
    return state

def step_approval_gate(state: OrpheusState, *, approver=None) -> OrpheusState:
    """
    Human-in-the-loop approval gate with rich display of counts, filters, vision usage, draft paths.
    """
    approved = False
    
    if callable(approver):
        # The approver function will display rich information about the state
        approved = bool(approver(state))
    else:
        # Default approval for non-interactive mode
        logger.info("No approver provided, defaulting to approved=False")
        approved = False
    
    state["approved"] = approved
    logger.info(f"Approval gate result: {approved}")
    
    return state

def step_publish(state: OrpheusState) -> OrpheusState:
    """Write enhanced markdown + jsonl evidence if approved."""
    import json
    from datetime import datetime
    from ..core.report_templates import get_report_template
    from ..core.enhanced_evidence import create_enhanced_evidence_pack
    from ..core.output_validator import get_output_validator
    
    if not state.get("approved"):
        logger.info("Report not approved, skipping publish")
        return state
    
    actor = state.get("actor", "unknown")
    draft_report = state.get("draft_report", "")
    evidence = state.get("evidence", [])
    
    logger.info(f"Publishing enhanced report for {actor}")
    
    # Create output directory
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Generate filenames with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_orpheus_{actor}_{timestamp}.md"
    evidence_filename = f"evidence_orpheus_{actor}_{timestamp}.jsonl"
    validation_filename = f"validation_orpheus_{actor}_{timestamp}.md"
    
    report_path = reports_dir / report_filename
    evidence_path = reports_dir / evidence_filename
    validation_path = reports_dir / validation_filename
    
    try:
        # Generate enhanced report using template
        metadata = {
            "tlp": "CLEAR",
            "actor": actor,
            "evidence_count": len(evidence),
            "generation_method": "orpheus_template"
        }
        
        template = get_report_template("threat_profile", actor, evidence, metadata)
        enhanced_report = template.generate_full_report()
        
        # Write enhanced markdown report
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(enhanced_report)
        
        # Create enhanced evidence pack
        evidence_pack = create_enhanced_evidence_pack(evidence, actor, metadata)
        enhanced_pack = evidence_pack.create_enhanced_pack()
        
        # Write enhanced evidence pack
        with open(evidence_path, 'w', encoding='utf-8') as f:
            for item in enhanced_pack:
                f.write(json.dumps(item, default=str) + '\n')
        
        # Validate outputs
        validator = get_output_validator()
        report_validation = validator.validate_markdown_report(enhanced_report, len(evidence))
        evidence_validation = validator.validate_evidence_pack(enhanced_pack)
        
        validations = {
            "markdown_report": report_validation,
            "evidence_pack": evidence_validation
        }
        
        # Generate validation report
        validation_report = validator.generate_validation_report(validations)
        
        with open(validation_path, 'w', encoding='utf-8') as f:
            f.write(validation_report)
        
        # Update state with outputs and validation
        state["outputs"] = {
            "report_md": str(report_path),
            "evidence_jsonl": str(evidence_path),
            "validation_report": str(validation_path),
            "report_size": len(enhanced_report),
            "evidence_count": len(enhanced_pack),
            "validation": {
                "report_valid": report_validation.get("valid", False),
                "report_score": report_validation.get("score", 0.0),
                "evidence_valid": evidence_validation.get("valid", False),
                "evidence_score": evidence_validation.get("score", 0.0)
            }
        }
        
        logger.info(f"Published enhanced report to {report_path}")
        logger.info(f"Published enhanced evidence to {evidence_path}")
        logger.info(f"Published validation report to {validation_path}")
        
    except Exception as e:
        logger.error(f"Failed to publish enhanced report: {e}")
        state["outputs"] = {"error": str(e)}
    
    return state

# ---- Build the LangGraph (linear with one gate)
def build_orpheus_graph(approver=None):
    g = StateGraph(OrpheusState)

    g.add_node("resolve", step_resolve)
    g.add_node("expand", step_expand)
    g.add_node("retrieve", step_retrieve)
    g.add_node("summarize", step_summarize)
    # approval is a closure that carries the approver
    def _gate(state: OrpheusState):
        return step_approval_gate(state, approver=approver)
    g.add_node("approval", _gate)
    g.add_node("publish", step_publish)

    g.set_entry_point("resolve")
    g.add_edge("resolve", "expand")
    g.add_edge("expand", "retrieve")
    g.add_edge("retrieve", "summarize")
    g.add_edge("summarize", "approval")
    # branch: if not approved, end; if approved, publish then end
    g.add_conditional_edges(
        "approval",
        lambda s: "publish" if s.get("approved") else "end",
        {"publish": "publish", "end": END}
    )
    g.add_edge("publish", END)

    return g.compile()
