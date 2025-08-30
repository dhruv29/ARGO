

import os
import time
import json
from pathlib import Path
from typing import Optional
from datetime import datetime
import typer
from rich.console import Console
from rich.prompt import Confirm
import psycopg
from argo.runbooks.orpheus_graph import build_orpheus_graph, OrpheusState
from argo.core.ingest import ingest_directory
from argo.core.embed import embed_all_chunks, get_embedding_stats
from argo.core.faiss_index import build_faiss_index
from argo.core.retrieve import retrieve
from argo.core.logging_config import configure_logging, get_audit_logger, log_approval_gate
from argo.core.approval_policy import load_policy_from_env
from argo.core.stix_export import export_orpheus_results_to_stix
from argo.core.runbook_state import get_runbook_state_manager
from argo.core.output_validator import get_output_validator

app = typer.Typer(help="Argo CLI — The Argonauts SOC Platform")
console = Console()

# Initialize structured logging
configure_logging(
    log_level=os.getenv("LOG_LEVEL", "INFO"),
    json_logs=os.getenv("JSON_LOGS", "false").lower() == "true"
)

@app.command()
def ingest(
    path: str,
    min_tokens: int = typer.Option(300, help="Minimum tokens per chunk"),
    max_tokens: int = typer.Option(800, help="Maximum tokens per chunk"),
    no_ocr: bool = typer.Option(False, "--no-ocr", help="Disable OCR fallback"),
):
    """Ingest PDF files from a directory into the database."""
    console.print(f"[bold]Ingesting PDFs from:[/] {path}")
    
    # Validate path
    input_path = Path(path)
    if not input_path.exists():
        console.print(f"[red]Error:[/] Path {path} does not exist")
        raise typer.Exit(1)
    
    if not input_path.is_dir():
        console.print(f"[red]Error:[/] Path {path} is not a directory")
        raise typer.Exit(1)
    
    # Setup paths
    workspace_root = Path.cwd()
    object_store_dir = workspace_root / "object_store"
    
    # Database URL from environment
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    try:
        with console.status("[bold green]Processing PDFs..."):
            results = ingest_directory(
                directory_path=input_path,
                object_store_dir=object_store_dir,
                db_url=db_url,
                min_tokens=min_tokens,
                max_tokens=max_tokens,
                use_ocr_fallback=not no_ocr
            )
        
        # Summary
        total_docs = len(results)
        total_chunks = sum(len(chunks) for _, chunks in results)
        
        console.print(f"[green]✅ Ingestion complete![/]")
        console.print(f"[bold]Documents processed:[/] {total_docs}")
        console.print(f"[bold]Total chunks created:[/] {total_chunks}")
        
        if results:
            console.print(f"[bold]Files stored in:[/] {object_store_dir}")
            console.print(f"[bold]Database:[/] {db_url}")
        
    except Exception as e:
        console.print(f"[red]Error during ingestion:[/] {e}")
        raise typer.Exit(1)

def _approver(state: OrpheusState) -> bool:
    console.rule("[bold yellow]🔍 Orpheus: Policy-Driven Approval Gate")
    
    # Initialize policy engine and audit logging
    policy_engine = load_policy_from_env()
    
    # Try to load from config directory first
    config_policy_path = Path("./config/approval_policy.yaml")
    if config_policy_path.exists():
        # Set environment variable for policy path
        os.environ["APPROVAL_POLICY_PATH"] = str(config_policy_path)
        policy_engine = load_policy_from_env()
        console.print(f"[dim]Loaded policy from: {config_policy_path}[/]")
    else:
        console.print(f"[dim]Using default policy[/]")
    audit_logger = state.get("audit_logger") or get_audit_logger("approval_gate")
    start_time = time.time()
    
    actor = state.get("actor", "(unknown)")
    aliases = state.get("aliases", [])
    ttps = state.get("ttps", [])
    cves = state.get("cves", [])
    evidence = state.get("evidence", [])
    draft_report = state.get("draft_report", "")
    plan = state.get("plan", {})
    
    # Display actor information
    console.print(f"[bold blue]🎯 Target Actor:[/] {actor}")
    if aliases:
        console.print(f"[bold blue]📋 Aliases:[/] {', '.join(aliases[:5])}")
        if len(aliases) > 5:
            console.print(f"   ... and {len(aliases) - 5} more")
    
    # Display expansion results
    console.print()
    console.print(f"[bold green]🔧 TTPs Found:[/] {len(ttps)}")
    if ttps and len(ttps) <= 5:
        console.print(f"   {', '.join(ttps)}")
    elif ttps:
        console.print(f"   {', '.join(ttps[:5])} ... and {len(ttps) - 5} more")
    
    console.print(f"[bold green]🚨 CVEs Found:[/] {len(cves)}")
    if cves and len(cves) <= 5:
        console.print(f"   {', '.join(cves)}")
    elif cves:
        console.print(f"   {', '.join(cves[:5])} ... and {len(cves) - 5} more")
    
    # Display evidence statistics
    console.print()
    console.print(f"[bold cyan]📊 Evidence Statistics:[/]")
    console.print(f"   Total Chunks: {len(evidence)}")
    
    evidence_stats = {}
    if evidence:
        sources = {}
        docs = set()
        confidences = []
        high_conf = 0
        
        for ev in evidence:
            source = getattr(ev, 'source', 'unknown') if hasattr(ev, 'source') else ev.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1
            
            doc_id = getattr(ev, 'document_id', 'unknown') if hasattr(ev, 'document_id') else ev.get('document_id', 'unknown')
            docs.add(doc_id)
            
            confidence = getattr(ev, 'confidence', 0.5) if hasattr(ev, 'confidence') else ev.get('confidence', 0.5)
            confidences.append(confidence)
            if confidence > 0.8:
                high_conf += 1
        
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        evidence_stats = {
            "total_evidence": len(evidence),
            "unique_documents": len(docs),
            "unique_sources": len(sources),
            "high_confidence_count": high_conf,
            "avg_confidence": avg_confidence,
            "sources_breakdown": sources
        }
        
        console.print(f"   Documents: {len(docs)}")
        console.print(f"   High Confidence (>0.8): {high_conf}")
        console.print(f"   Average Confidence: {avg_confidence:.3f}")
        console.print(f"   Sources: {dict(sources)}")
        
        # Coverage metrics
        coverage_score = evidence_stats.get("coverage_score", 0.0)
        counter_evidence_count = evidence_stats.get("counter_evidence_count", 0)
        
        console.print(f"   Coverage Score: {coverage_score:.3f}")
        console.print(f"   Counter-Evidence: {counter_evidence_count}")
    
    # Policy evaluation
    console.print()
    console.rule("[bold magenta]📋 Policy Evaluation")
    
    policy_eval = policy_engine.evaluate_state(state)
    
    # Display policy results
    console.print(f"[bold]Policy:[/] {policy_engine.policy.name}")
    console.print(f"[bold]Overall Score:[/] {policy_eval.total_score:.2f} / 1.00")
    
    if policy_eval.approved:
        console.print(f"[bold green]Status:[/] ✅ APPROVED")
    else:
        console.print(f"[bold red]Status:[/] ❌ NOT APPROVED")
    
    console.print()
    console.print("[bold]Rule Evaluation:[/]")
    for rule_name, result in policy_eval.rule_results.items():
        status_icon = "✅" if result["passed"] else "❌"
        required_label = " [red](REQUIRED)[/]" if result["required"] else ""
        
        actual = result.get("actual_value")
        threshold = result.get("threshold")
        
        if actual is not None and threshold is not None:
            console.print(f"   {status_icon} {rule_name}: {actual:.2f} / {threshold:.2f}{required_label}")
        else:
            console.print(f"   {status_icon} {rule_name}{required_label}")
        
        console.print(f"      {result['description']}")
    
    # Display recommendation
    console.print()
    console.print(f"[bold yellow]📝 Recommendation:[/]")
    recommendation_lines = policy_eval.recommendation.split('\n')
    for line in recommendation_lines:
        console.print(f"   {line}")
    
    # Handle alias candidates if any
    alias_write_approved = False
    if state.get("needs_alias_write_approval"):
        console.print()
        console.rule("[bold cyan]🔍 New Aliases Discovered via RAG-LLM")
        alias_candidates = state.get("alias_candidates", [])
        for candidate in alias_candidates:
            alias_name = candidate.get('alias', 'unknown')
            confidence = candidate.get('confidence', 0.0)
            doc_id = candidate.get('doc_id', 'unknown')
            page = candidate.get('page', 'unknown')
            snippet = candidate.get('snippet', '')[:80]
            
            console.print(f"[bold yellow]• {alias_name}[/] [dim](conf={confidence:.2f})[/]")
            console.print(f"   Source: {doc_id} page {page}")
            console.print(f"   Evidence: \"{snippet}...\"")
        
        console.print()
        alias_write_approved = Confirm.ask("💾 Approve writing these aliases to the knowledge graph?", default=False)
        state["approved_alias_write"] = alias_write_approved
        
        if alias_write_approved:
            console.print("[green]✅ Alias write approved[/]")
        else:
            console.print("[yellow]⚠️  Alias write declined - aliases will not be saved[/]")
    
    # Show draft report preview
    console.print()
    console.print(f"[bold yellow]📄 Draft Report Preview:[/]")
    console.print(f"   Length: {len(draft_report)} characters")
    
    if draft_report:
        lines = draft_report.split('\n')[:3]
        for line in lines:
            if line.strip():
                preview = line[:100] + "..." if len(line) > 100 else line
                console.print(f"   {preview}")
    
    # Final approval decision
    console.print()
    console.print(f"[bold white]📁 Output Paths:[/]")
    console.print(f"   Report: reports/report_orpheus_{actor}_[timestamp].md")
    console.print(f"   Evidence: reports/evidence_orpheus_{actor}_[timestamp].jsonl")
    
    console.print()
    
    # Make final decision - policy can override but human has final say
    if policy_eval.approved:
        final_decision = Confirm.ask("🚀 Policy recommends approval. Publish report & evidence?", default=True)
    else:
        console.print("[yellow]⚠️  Policy recommends against publication[/]")
        final_decision = Confirm.ask("🚀 Override policy and publish anyway?", default=False)
    
    # Log approval gate decision
    decision_time_ms = (time.time() - start_time) * 1000
    log_approval_gate(
        audit_logger,
        state=state,
        decision=final_decision,
        decision_time_ms=decision_time_ms,
        evidence_stats=evidence_stats,
        approver_context={
            "policy_approved": policy_eval.approved,
            "policy_score": policy_eval.total_score,
            "policy_name": policy_engine.policy.name,
            "failed_rules": policy_eval.failed_required_rules,
            "alias_write_approved": alias_write_approved
        }
    )
    
    return final_decision

@app.command()
def run(
    agent: str,
    actor: str = typer.Option(None, help="Actor/Group name"),
    exposure: bool = typer.Option(False, "--exposure", help="Include exposure view")
):
    if agent.lower() != "orpheus":
        console.print(f"[red]Unsupported agent:[/] {agent} (only 'orpheus' for now)")
        raise typer.Exit(2)

    # Initialize audit logger
    audit_logger = get_audit_logger("orpheus_execution")
    start_time = time.time()
    
    audit_logger.info(
        "orpheus_execution_started",
        actor=actor or "",
        agent=agent,
        exposure_enabled=exposure,
        event_type="execution_start"
    )

    graph = build_orpheus_graph(approver=_approver)
    initial: OrpheusState = {"run_id": "local-run", "actor": actor or "", "audit_logger": audit_logger}

    # LangGraph runnable interface
    final_state: OrpheusState = graph.invoke(initial)
    
    execution_time_ms = (time.time() - start_time) * 1000
    
    if final_state.get("approved"):
        out = final_state.get("outputs", {})
        console.print(f"[green]Published[/] -> {out}")
        
        audit_logger.info(
            "orpheus_execution_completed",
            actor=actor or "",
            execution_time_ms=execution_time_ms,
            approved=True,
            outputs=out,
            evidence_count=len(final_state.get("evidence", [])),
            aliases_discovered=len(final_state.get("aliases", [])),
            event_type="execution_completion"
        )
    else:
        console.print("[yellow]Draft not approved; nothing published.[/]")
        
        audit_logger.info(
            "orpheus_execution_completed",
            actor=actor or "",
            execution_time_ms=execution_time_ms,
            approved=False,
            evidence_count=len(final_state.get("evidence", [])),
            aliases_discovered=len(final_state.get("aliases", [])),
            event_type="execution_completion"
        )
    return

@app.command()
def embed(
    batch_size: int = typer.Option(100, help="Batch size for embedding generation"),
    force: bool = typer.Option(False, "--force", help="Re-embed chunks that already have embeddings")
):
    """Generate embeddings for document chunks."""
    # Database URL from environment
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    try:
        # Get current stats
        stats = get_embedding_stats(db_url)
        console.print(f"[bold]Embedding Status:[/]")
        console.print(f"Total chunks: {stats['total_chunks']}")
        console.print(f"Embedded chunks: {stats['embedded_chunks']}")
        console.print(f"Pending chunks: {stats['pending_chunks']}")
        console.print(f"Completion rate: {stats['completion_rate']:.1%}")
        
        if stats['pending_chunks'] == 0 and not force:
            console.print("[green]✅ All chunks already have embeddings![/]")
            return
        
        # Generate embeddings
        with console.status("[bold green]Generating embeddings..."):
            processed = embed_all_chunks(db_url, batch_size)
        
        console.print(f"[green]✅ Generated embeddings for {processed} chunks![/]")
        
        # Show updated stats
        updated_stats = get_embedding_stats(db_url)
        console.print(f"[bold]Updated completion rate:[/] {updated_stats['completion_rate']:.1%}")
        
    except Exception as e:
        console.print(f"[red]Error generating embeddings:[/] {e}")
        raise typer.Exit(1)


@app.command()
def status():
    """Show system status and statistics."""
    # Database URL from environment
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    
    try:
        # Get embedding stats
        stats = get_embedding_stats(db_url)
        
        console.print("[bold]🚀 Argo System Status[/]")
        console.print()
        console.print("[bold]📊 Documents & Chunks:[/]")
        console.print(f"  Total chunks: {stats['total_chunks']}")
        console.print(f"  Embedded chunks: {stats['embedded_chunks']}")
        console.print(f"  Pending embeddings: {stats['pending_chunks']}")
        console.print(f"  Completion rate: {stats['completion_rate']:.1%}")
        
        if stats['models_used']:
            console.print()
            console.print("[bold]🤖 Embedding Models:[/]")
            for model, count in stats['models_used'].items():
                console.print(f"  {model}: {count} chunks")
        
        # Check object store
        workspace_root = Path.cwd()
        object_store_dir = workspace_root / "object_store"
        if object_store_dir.exists():
            pdf_files = list(object_store_dir.glob("*.pdf"))
            console.print()
            console.print(f"[bold]📁 Object Store:[/] {len(pdf_files)} PDF files")
        
        console.print()
        console.print(f"[bold]🗄️  Database:[/] {db_url}")
        
    except Exception as e:
        console.print(f"[red]Error getting status:[/] {e}")
        raise typer.Exit(1)


@app.command()
def index(
    force: bool = typer.Option(False, "--force", help="Force rebuild of FAISS index"),
    index_path: str = typer.Option("./faiss_index", help="Path to store FAISS index")
):
    """Build FAISS index from embeddings."""
    # Database URL from environment
    db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
    index_path_obj = Path(index_path)
    
    try:
        # Check if embeddings exist
        stats = get_embedding_stats(db_url)
        if stats['embedded_chunks'] == 0:
            console.print("[red]No embeddings found! Run 'argo embed' first.[/]")
            raise typer.Exit(1)
        
        console.print(f"[bold]Building FAISS index from {stats['embedded_chunks']} embeddings...[/]")
        
        with console.status("[bold green]Building FAISS index..."):
            manager = build_faiss_index(db_url, index_path_obj, force_rebuild=force)
        
        # Get index stats
        index_stats = manager.get_stats()
        
        console.print(f"[green]✅ FAISS index built successfully![/]")
        console.print(f"[bold]Index type:[/] {index_stats['index_type']}")
        console.print(f"[bold]Total vectors:[/] {index_stats['total_vectors']}")
        console.print(f"[bold]Dimensions:[/] {index_stats['dimensions']}")
        console.print(f"[bold]Index saved to:[/] {index_path_obj}")
        
    except Exception as e:
        console.print(f"[red]Error building FAISS index:[/] {e}")
        raise typer.Exit(1)


@app.command()
def export_stix(
    actor: str,
    output_dir: str = typer.Option("./reports", help="Output directory for STIX files")
):
    """Export CTI data to STIX 2.1 bundle for interoperability."""
    console.print(f"[bold]Exporting STIX bundle for actor:[/] {actor}")
    
    # Validate output directory
    output_path = Path(output_dir)
    if not output_path.exists():
        output_path.mkdir(parents=True, exist_ok=True)
        console.print(f"[green]Created output directory:[/] {output_path}")
    
    try:
        # Get actor data from database
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
        
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                # Get actor aliases
                cur.execute("""
                    SELECT DISTINCT a.name FROM alias a
                    JOIN actor act ON a.actor_id = act.id
                    WHERE act.id = %s OR %s = ANY(act.names)
                """, (actor, actor))
                
                aliases = [row[0] for row in cur.fetchall() if row[0]]
                if not aliases:
                    aliases = [actor]  # Fallback to original name
                
                # Get techniques
                cur.execute("""
                    SELECT DISTINCT t.t_id FROM technique t
                    JOIN cve_technique ct ON ct.t_id = t.t_id
                    JOIN cve c ON ct.cve_id = c.id
                    JOIN actor_cve ac ON ac.cve_id = c.id
                    JOIN actor a ON ac.actor_id = a.id
                    WHERE a.id = %s OR %s = ANY(a.names)
                """, (actor, actor))
                
                techniques = [row[0] for row in cur.fetchall() if row[0]]
                
                # Get CVEs
                cur.execute("""
                    SELECT DISTINCT c.id FROM cve c
                    JOIN actor_cve ac ON ac.cve_id = c.id
                    JOIN actor a ON ac.actor_id = a.id
                    WHERE a.id = %s OR %s = ANY(a.names)
                """, (actor, actor))
                
                cves = [row[0] for row in cur.fetchall() if row[0]]
        
        # Get evidence from recent search
        console.print(f"[bold]Retrieving evidence for export...[/]")
        evidence = retrieve(actor, namespaces=("personal",), topk=20)
        
        if not evidence:
            console.print("[yellow]No evidence found for export[/]")
            return
        
        # Export to STIX
        with console.status("[bold green]Generating STIX bundle..."):
            export_result = export_orpheus_results_to_stix(
                actor=actor,
                aliases=aliases,
                techniques=techniques,
                cves=cves,
                evidence=evidence,
                output_dir=output_path
            )
        
        console.print(f"[green]✅ STIX export completed![/]")
        console.print(f"[bold]Bundle ID:[/] {export_result['bundle_id']}")
        console.print(f"[bold]Objects:[/] {export_result['total_objects']}")
        console.print(f"[bold]Output:[/] {export_result['output_path']}")
        
        # Show object type breakdown
        console.print(f"\n[bold]Object Types:[/]")
        for obj_type, count in export_result['object_types'].items():
            console.print(f"  {obj_type}: {count}")
        
    except Exception as e:
        console.print(f"[red]Error during STIX export:[/] {e}")
        raise typer.Exit(1)


@app.command()
def list_runs(
    limit: int = typer.Option(20, help="Maximum number of runs to display")
):
    """List recent runbook executions with state information."""
    console.print(f"[bold]Listing recent runbook executions (limit: {limit})[/]")
    
    try:
        state_manager = get_runbook_state_manager()
        runs = state_manager.list_runs(limit=limit)
        
        if not runs:
            console.print("[yellow]No runbook executions found[/]")
            return
        
        console.print(f"\n[green]Found {len(runs)} runs:[/]\n")
        
        for i, run in enumerate(runs, 1):
            console.print(f"[bold]{i}. Run ID:[/] {run['run_id']}")
            console.print(f"   [blue]Timestamp:[/] {run['timestamp']}")
            console.print(f"   [blue]Execution Time:[/] {run['execution_time_ms']:.0f}ms")
            console.print(f"   [blue]Nodes:[/] {run['node_count']}")
            console.print(f"   [blue]Status:[/] {run['status']}")
            console.print()
        
    except Exception as e:
        console.print(f"[red]Error listing runs:[/] {e}")
        raise typer.Exit(1)


@app.command()
def replay_run(
    run_id: str,
    target_node: Optional[str] = typer.Option(None, help="Node to replay up to")
):
    """Replay a specific runbook execution."""
    console.print(f"[bold]Replaying run:[/] {run_id}")
    
    if target_node:
        console.print(f"[bold]Target node:[/] {target_node}")
    
    try:
        state_manager = get_runbook_state_manager()
        replay_results = state_manager.replay_run(run_id, target_node)
        
        if "error" in replay_results:
            console.print(f"[red]Replay failed:[/] {replay_results['error']}")
            raise typer.Exit(1)
        
        console.print(f"[green]✅ Replay completed successfully![/]")
        console.print(f"[bold]Nodes executed:[/] {len(replay_results['executed_nodes'])}")
        
        if replay_results["executed_nodes"]:
            console.print(f"\n[bold]Execution summary:[/]")
            for node_exec in replay_results["executed_nodes"]:
                console.print(f"  • {node_exec['node_name']}: {node_exec['execution_time_ms']:.0f}ms")
        
        if replay_results["final_state"]:
            console.print(f"\n[bold]Final state keys:[/] {list(replay_results['final_state'].keys())}")
        
    except Exception as e:
        console.print(f"[red]Error during replay:[/] {e}")
        raise typer.Exit(1)


@app.command()
def validate_outputs(
    report_path: Optional[str] = typer.Option(None, help="Path to markdown report"),
    evidence_path: Optional[str] = typer.Option(None, help="Path to evidence pack"),
    stix_path: Optional[str] = typer.Option(None, help="Path to STIX bundle")
):
    """Validate Orpheus outputs for quality and completeness."""
    console.print("[bold]🔍 Validating Orpheus Outputs[/]")
    
    if not any([report_path, evidence_path, stix_path]):
        console.print("[yellow]No paths specified. Validating all outputs in reports/ directory...[/]")
        
        reports_dir = Path("reports")
        if not reports_dir.exists():
            console.print("[red]Reports directory not found[/]")
            raise typer.Exit(1)
        
        # Find all output files
        report_files = list(reports_dir.glob("report_orpheus_*.md"))
        evidence_files = list(reports_dir.glob("evidence_orpheus_*.jsonl"))
        stix_files = list(reports_dir.glob("*.json"))  # STIX exports
        
        if not any([report_files, evidence_files, stix_files]):
            console.print("[yellow]No Orpheus outputs found in reports/ directory[/]")
            raise typer.Exit(1)
        
        # Validate found files
        if report_files:
            report_path = str(report_files[-1])  # Most recent
        if evidence_files:
            evidence_path = str(evidence_files[-1])  # Most recent
        if stix_files:
            stix_path = str(stix_files[-1])  # Most recent
    
    validator = get_output_validator()
    validations = {}
    
    try:
        # Validate markdown report
        if report_path and Path(report_path).exists():
            console.print(f"[blue]Validating report:[/] {report_path}")
            
            with open(report_path, 'r', encoding='utf-8') as f:
                report_content = f.read()
            
            # Estimate evidence count from citations
            import re
            citations = re.findall(r'\[Evidence \d+\]', report_content)
            evidence_count = len(set(citations))
            
            report_validation = validator.validate_markdown_report(report_content, evidence_count)
            validations["markdown_report"] = report_validation
            
            status = "✅ VALID" if report_validation.get("valid", False) else "❌ INVALID"
            score = report_validation.get("score", 0.0)
            console.print(f"   Status: {status}")
            console.print(f"   Score: {score:.2f}/1.00")
        
        # Validate evidence pack
        if evidence_path and Path(evidence_path).exists():
            console.print(f"[blue]Validating evidence pack:[/] {evidence_path}")
            
            evidence_pack = []
            with open(evidence_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        evidence_pack.append(json.loads(line))
            
            evidence_validation = validator.validate_evidence_pack(evidence_pack)
            validations["evidence_pack"] = evidence_validation
            
            status = "✅ VALID" if evidence_validation.get("valid", False) else "❌ INVALID"
            score = evidence_validation.get("score", 0.0)
            console.print(f"   Status: {status}")
            console.print(f"   Score: {score:.2f}/1.00")
        
        # Validate STIX export
        if stix_path and Path(stix_path).exists():
            console.print(f"[blue]Validating STIX export:[/] {stix_path}")
            
            with open(stix_path, 'r', encoding='utf-8') as f:
                stix_bundle = json.load(f)
            
            stix_validation = validator.validate_stix_export(stix_bundle)
            validations["stix_export"] = stix_validation
            
            status = "✅ VALID" if stix_validation.get("valid", False) else "❌ INVALID"
            score = stix_validation.get("score", 0.0)
            console.print(f"   Status: {status}")
            console.print(f"   Score: {score:.2f}/1.00")
        
        # Generate comprehensive validation report
        if validations:
            console.print(f"\n[bold]📋 Validation Summary[/]")
            
            overall_valid = all(v.get("valid", False) for v in validations.values())
            overall_status = "✅ ALL VALID" if overall_valid else "❌ SOME INVALID"
            console.print(f"Overall Status: {overall_status}")
            
            # Generate detailed validation report
            validation_report = validator.generate_validation_report(validations)
            
            # Save validation report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            validation_path = f"reports/validation_summary_{timestamp}.md"
            
            with open(validation_path, 'w', encoding='utf-8') as f:
                f.write(validation_report)
            
            console.print(f"\n[green]Validation report saved to:[/] {validation_path}")
            
            # Show key recommendations
            console.print(f"\n[bold]💡 Key Recommendations[/]")
            for output_type, validation in validations.items():
                if validation.get("recommendations"):
                    console.print(f"\n[blue]{output_type.replace('_', ' ').title()}:[/]")
                    for rec in validation["recommendations"][:2]:  # Show top 2
                        console.print(f"  • {rec}")
        
        else:
            console.print("[yellow]No valid outputs found to validate[/]")
        
    except Exception as e:
        console.print(f"[red]Error during validation:[/] {e}")
        raise typer.Exit(1)


@app.command()
def search(
    query: str,
    limit: int = typer.Option(15, help="Maximum number of results"),
    namespace: str = typer.Option("personal", help="Namespace to search in")
):
    """Search for documents using hybrid retrieval (FAISS + BM25)."""
    audit_logger = get_audit_logger("search")
    start_time = time.time()
    
    try:
        console.print(f"[bold]Searching for:[/] '{query}'")
        console.print(f"[bold]Namespace:[/] {namespace}")
        console.print(f"[bold]Limit:[/] {limit}")
        console.print()
        
        with console.status("[bold green]Searching..."):
            results = retrieve(query, namespaces=(namespace,), topk=limit)
        
        execution_time_ms = (time.time() - start_time) * 1000
        
        if not results:
            console.print("[yellow]No results found.[/]")
            audit_logger.info(
                "search_completed",
                query=query,
                namespace=namespace,
                limit=limit,
                results_count=0,
                execution_time_ms=execution_time_ms,
                event_type="search"
            )
            return
        
        # Log successful search
        sources_used = list(set(evidence.source for evidence in results))
        audit_logger.info(
            "search_completed",
            query=query,
            namespace=namespace,
            limit=limit,
            results_count=len(results),
            sources_used=sources_used,
            execution_time_ms=execution_time_ms,
            avg_confidence=sum(evidence.confidence for evidence in results) / len(results),
            event_type="search"
        )
        
        console.print(f"[green]Found {len(results)} results:[/]")
        console.print()
        
        for i, evidence in enumerate(results, 1):
            console.print(f"[bold]{i}. Document {evidence.document_id} (Page {evidence.page})[/]")
            console.print(f"   [blue]Source:[/] {evidence.source}")
            console.print(f"   [blue]Score:[/] {evidence.score:.3f}")
            console.print(f"   [blue]Confidence:[/] {evidence.confidence:.3f}")
            console.print(f"   [blue]TLP:[/] {evidence.tlp}")
            if evidence.actors:
                console.print(f"   [blue]Actors:[/] {', '.join(evidence.actors)}")
            if evidence.cves:
                console.print(f"   [blue]CVEs:[/] {', '.join(evidence.cves)}")
            if evidence.techniques:
                console.print(f"   [blue]Techniques:[/] {', '.join(evidence.techniques)}")
            console.print(f"   [green]Snippet:[/] {evidence.snippet}")
            console.print()
        
    except Exception as e:
        console.print(f"[red]Error during search:[/] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
