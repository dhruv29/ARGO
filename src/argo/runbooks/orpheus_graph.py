from typing import TypedDict, Literal, Optional, Dict, Any, List
from langgraph.graph import StateGraph, END

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

# ---- Step functions (call into your core modules; stubbed now)
def step_resolve(state: OrpheusState) -> OrpheusState:
    # TODO: resolve actor -> canonical id, aliases (via PG)
    state.setdefault("aliases", [])
    state["plan"] = {"router": "regex", "namespaces": ["personal", "global"]}
    return state

def step_expand(state: OrpheusState) -> OrpheusState:
    # TODO: expand -> ttps, cves using PG joins
    state.setdefault("ttps", [])
    state.setdefault("cves", [])
    return state

def step_retrieve(state: OrpheusState) -> OrpheusState:
    # TODO: call core.retrieve.retrieve() with plan; return top-k evidence
    state["evidence"] = []
    return state

def step_summarize(state: OrpheusState) -> OrpheusState:
    # TODO: call core.summarize to produce markdown strictly from evidence
    state["draft_report"] = f"# Orpheus Profile: {state.get('actor','(unknown)')}\n\n> DRAFT"
    return state

def step_approval_gate(state: OrpheusState, *, approver=None) -> OrpheusState:
    """
    Human-in-the-loop. If `approver` callable supplied (from CLI), ask user;
    otherwise default to False.
    """
    approved = False
    if callable(approver):
        approved = bool(approver(state))
    state["approved"] = approved
    return state

def step_publish(state: OrpheusState) -> OrpheusState:
    # TODO: write markdown + jsonl evidence if approved
    if state.get("approved"):
        state["outputs"] = {
            "report_md": f"reports/report_orpheus_{state['actor']}.md",
            "evidence_jsonl": f"reports/evidence_orpheus_{state['actor']}.jsonl",
        }
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
