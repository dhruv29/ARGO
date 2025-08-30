

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
from argo.cli.config_manager import get_config_manager
from argo.cli.workflow_manager import get_workflow_manager
from argo.cli.help_system import get_help_system
from argo.core.watch_folder import get_watch_folder_manager

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


@app.command()
def config(
    action: str = typer.Argument(..., help="Action: show, set, reset, validate"),
    key: Optional[str] = typer.Argument(None, help="Configuration key"),
    value: Optional[str] = typer.Argument(None, help="Configuration value")
):
    """Manage Argo configuration settings."""
    console.print(f"[bold]🔧 Configuration Management[/]")
    
    if action == "show":
        _show_configuration()
    elif action == "set":
        if not key or not value:
            console.print("[red]Error:[/] Both key and value required for 'set' action")
            raise typer.Exit(1)
        _set_configuration(key, value)
    elif action == "reset":
        if not key:
            console.print("[red]Error:[/] Key required for 'reset' action")
            raise typer.Exit(1)
        _reset_configuration(key)
    elif action == "validate":
        _validate_configuration()
    else:
        console.print(f"[red]Error:[/] Unknown action: {action}")
        console.print("Available actions: show, set, reset, validate")
        raise typer.Exit(1)


def _show_configuration():
    """Display current configuration."""
    config_items = {
        "Database": os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter"),
        "OpenAI API Key": "***" if os.getenv("OPENAI_API_KEY") else "Not set",
        "Log Level": os.getenv("LOG_LEVEL", "INFO"),
        "JSON Logs": os.getenv("JSON_LOGS", "false"),
        "Policy Path": os.getenv("APPROVAL_POLICY_PATH", "default"),
        "Runbook State Dir": os.getenv("RUNBOOK_STATE_DIR", "./runbook_states"),
        "Local Embedding Model": os.getenv("LOCAL_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    }
    
    console.print("\n[bold]Current Configuration:[/]")
    for key, value in config_items.items():
        console.print(f"  [blue]{key}:[/] {value}")


def _set_configuration(key: str, value: str):
    """Set a configuration value."""
    # This is a simplified version - in production, you'd want to persist to a config file
    os.environ[key] = value
    console.print(f"[green]✅ Set {key} = {value}[/]")
    console.print("[yellow]Note:[/] This change is only for the current session")


def _reset_configuration(key: str):
    """Reset a configuration value to default."""
    if key in os.environ:
        del os.environ[key]
        console.print(f"[green]✅ Reset {key} to default[/]")
    else:
        console.print(f"[yellow]Note:[/] {key} was not set")


def _validate_configuration():
    """Validate current configuration."""
    console.print("[bold]Validating configuration...[/]")
    
    issues = []
    
    # Check required settings
    if not os.getenv("DATABASE_URL"):
        issues.append("DATABASE_URL not set")
    
    if not os.getenv("OPENAI_API_KEY"):
        issues.append("OPENAI_API_KEY not set")
    
    # Check database connectivity
    try:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        console.print("[green]✅ Database connection: OK[/]")
    except Exception as e:
        issues.append(f"Database connection failed: {e}")
    
    # Check policy file
    policy_path = Path("./config/approval_policy.yaml")
    if policy_path.exists():
        console.print("[green]✅ Policy file: Found[/]")
    else:
        issues.append("Policy file not found: config/approval_policy.yaml")
    
    if issues:
        console.print(f"\n[red]❌ Configuration issues found:[/]")
        for issue in issues:
            console.print(f"  • {issue}")
        raise typer.Exit(1)
    else:
        console.print(f"\n[green]✅ Configuration validation passed![/]")


@app.command()
def batch(
    operation: str = typer.Argument(..., help="Operation: ingest, embed, index, analyze"),
    input_path: str = typer.Argument(..., help="Input directory or file pattern"),
    config_file: Optional[str] = typer.Option(None, "--config", help="Batch configuration file")
):
    """Execute batch operations on multiple inputs."""
    console.print(f"[bold]🔄 Batch Operation: {operation}[/]")
    
    if operation == "ingest":
        _batch_ingest(input_path, config_file)
    elif operation == "embed":
        _batch_embed(input_path, config_file)
    elif operation == "index":
        _batch_index(input_path, config_file)
    elif operation == "analyze":
        _batch_analyze(input_path, config_file)
    else:
        console.print(f"[red]Error:[/] Unknown operation: {operation}")
        console.print("Available operations: ingest, embed, index, analyze")
        raise typer.Exit(1)


def _batch_ingest(input_path: str, config_file: Optional[str]):
    """Execute batch ingestion."""
    console.print(f"[blue]Batch ingesting from:[/] {input_path}")
    
    # Parse input path pattern
    input_pattern = Path(input_path)
    if input_pattern.is_dir():
        # Directory - process all PDFs
        pdf_files = list(input_pattern.glob("**/*.pdf"))
        console.print(f"Found {len(pdf_files)} PDF files")
        
        if not pdf_files:
            console.print("[yellow]No PDF files found[/]")
            return
        
        # Process in batches
        batch_size = 5
        for i in range(0, len(pdf_files), batch_size):
            batch = pdf_files[i:i + batch_size]
            console.print(f"\n[bold]Processing batch {i//batch_size + 1}:[/] {len(batch)} files")
            
            for pdf_file in batch:
                try:
                    console.print(f"  Processing: {pdf_file.name}")
                    # Create temporary directory for single file
                    temp_dir = Path(f"./temp_batch_{pdf_file.stem}")
                    temp_dir.mkdir(exist_ok=True)
                    
                    # Copy file to temp directory
                    import shutil
                    shutil.copy2(pdf_file, temp_dir / pdf_file.name)
                    
                    # Ingest
                    ingest_directory(
                        directory_path=temp_dir,
                        object_store_dir=Path("./object_store"),
                        db_url=os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter"),
                        min_tokens=300,
                        max_tokens=800,
                        use_ocr_fallback=True
                    )
                    
                    # Cleanup
                    shutil.rmtree(temp_dir)
                    console.print(f"  [green]✅ {pdf_file.name} processed[/]")
                    
                except Exception as e:
                    console.print(f"  [red]❌ {pdf_file.name} failed: {e}[/]")
        
        console.print(f"\n[green]✅ Batch ingestion complete![/]")
        
    else:
        console.print("[red]Error:[/] Input path must be a directory for batch operations")


def _batch_embed(input_path: str, config_file: Optional[str]):
    """Execute batch embedding."""
    console.print(f"[blue]Batch embedding from:[/] {input_path}")
    
    try:
        with console.status("[bold green]Generating embeddings..."):
            results = embed_all_chunks(
                db_url=os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
            )
        
        console.print(f"[green]✅ Batch embedding complete![/]")
        console.print(f"[bold]Chunks processed:[/] {results.get('total_chunks', 0) if isinstance(results, dict) else 0}")
        console.print(f"[bold]Embeddings generated:[/] {results.get('embeddings_generated', 0) if isinstance(results, dict) else 0}")
        
    except Exception as e:
        console.print(f"[red]Error during batch embedding:[/] {e}")
        raise typer.Exit(1)


def _batch_index(input_path: str, config_file: Optional[str]):
    """Execute batch indexing."""
    console.print(f"[blue]Batch indexing from:[/] {input_path}")
    
    try:
        with console.status("[bold green]Building FAISS index..."):
            results = build_faiss_index(
                db_url=os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter"),
                index_path=Path("./faiss_index")
            )
        
        console.print(f"[green]✅ Batch indexing complete![/]")
        console.print(f"[bold]Index built:[/] {results.get('index_path', 'N/A') if isinstance(results, dict) else 'N/A'}")
        console.print(f"[bold]Vectors indexed:[/] {results.get('vector_count', 0) if isinstance(results, dict) else 0}")
        
    except Exception as e:
        console.print(f"[red]Error during batch indexing:[/] {e}")
        raise typer.Exit(1)


def _batch_analyze(input_path: str, config_file: Optional[str]):
    """Execute batch analysis."""
    console.print(f"[blue]Batch analysis from:[/] {input_path}")
    
    # This would be enhanced with actual batch analysis logic
    console.print("[yellow]Batch analysis not yet implemented[/]")


@app.command()
def interactive():
    """Start interactive Argo session."""
    console.print("[bold]🚀 Welcome to Interactive Argo![/]")
    console.print("Type 'help' for available commands, 'exit' to quit.\n")
    
    while True:
        try:
            command = input("argo> ").strip()
            
            if command.lower() in ['exit', 'quit', 'q']:
                console.print("[yellow]Goodbye![/]")
                break
            elif command.lower() == 'help':
                _show_interactive_help()
            elif command.lower() == 'status':
                _show_system_status()
            elif command.lower() == 'config':
                _show_configuration()
            elif command.lower().startswith('ingest '):
                path = command[7:].strip()
                console.print(f"[blue]Ingesting:[/] {path}")
                # This would execute the actual ingestion
                console.print("[yellow]Interactive ingestion not yet implemented[/]")
            elif command.lower().startswith('search '):
                query = command[7:].strip()
                console.print(f"[blue]Searching:[/] {query}")
                # This would execute the actual search
                console.print("[yellow]Interactive search not yet implemented[/]")
            elif command.lower().startswith('analyze '):
                actor = command[8:].strip()
                console.print(f"[blue]Analyzing actor:[/] {actor}")
                # This would execute Orpheus analysis
                console.print("[yellow]Interactive analysis not yet implemented[/]")
            else:
                console.print(f"[red]Unknown command:[/] {command}")
                console.print("Type 'help' for available commands")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Use 'exit' to quit[/]")
        except Exception as e:
            console.print(f"[red]Error:[/] {e}")


def _show_interactive_help():
    """Show interactive mode help."""
    console.print("\n[bold]Interactive Commands:[/]")
    console.print("  [blue]help[/]     - Show this help")
    console.print("  [blue]status[/]   - Show system status")
    console.print("  [blue]config[/]   - Show configuration")
    console.print("  [blue]ingest <path>[/] - Ingest PDFs from path")
    console.print("  [blue]search <query>[/] - Search documents")
    console.print("  [blue]analyze <actor>[/] - Analyze threat actor")
    console.print("  [blue]exit[/]     - Quit interactive mode\n")


def _show_system_status():
    """Show system status in interactive mode."""
    console.print("\n[bold]System Status:[/]")
    
    # Database status
    try:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM document")
                doc_count = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM doc_chunk")
                chunk_count = cur.fetchone()[0]
        
        console.print(f"  [green]Database:[/] Connected")
        console.print(f"  [blue]Documents:[/] {doc_count}")
        console.print(f"  [blue]Chunks:[/] {chunk_count}")
        
    except Exception as e:
        console.print(f"  [red]Database:[/] Connection failed - {e}")
    
    # FAISS index status
    index_path = Path("./faiss_index")
    if index_path.exists():
        console.print(f"  [green]FAISS Index:[/] Available")
    else:
        console.print(f"  [yellow]FAISS Index:[/] Not built")
    
    # Reports directory
    reports_dir = Path("./reports")
    if reports_dir.exists():
        report_files = list(reports_dir.glob("*.md"))
        console.print(f"  [green]Reports:[/] {len(report_files)} available")
    else:
        console.print(f"  [yellow]Reports:[/] Directory not found")


@app.command()
def progress(
    operation: str = typer.Argument(..., help="Operation: ingest, embed, index, analyze"),
    show_details: bool = typer.Option(False, "--details", help="Show detailed progress")
):
    """Show progress for long-running operations."""
    console.print(f"[bold]📊 Progress: {operation}[/]")
    
    if operation == "ingest":
        _show_ingest_progress(show_details)
    elif operation == "embed":
        _show_embed_progress(show_details)
    elif operation == "index":
        _show_index_progress(show_details)
    elif operation == "analyze":
        _show_analyze_progress(show_details)
    else:
        console.print(f"[red]Error:[/] Unknown operation: {operation}")
        console.print("Available operations: ingest, embed, index, analyze")
        raise typer.Exit(1)


def _show_ingest_progress(show_details: bool):
    """Show ingestion progress."""
    try:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM document")
                total_docs = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM doc_chunk")
                total_chunks = cur.fetchone()[0]
                
                if show_details:
                    cur.execute("""
                        SELECT source, COUNT(*) as count 
                        FROM document 
                        GROUP BY source 
                        ORDER BY count DESC
                    """)
                    sources = cur.fetchall()
                    
                    cur.execute("""
                        SELECT DATE(created_at) as date, COUNT(*) as count 
                        FROM document 
                        GROUP BY DATE(created_at) 
                        ORDER BY date DESC 
                        LIMIT 7
                    """)
                    recent = cur.fetchall()
        
        console.print(f"[bold]Total Documents:[/] {total_docs}")
        console.print(f"[bold]Total Chunks:[/] {total_chunks}")
        
        if show_details and sources:
            console.print(f"\n[bold]By Source:[/]")
            for source, count in sources:
                console.print(f"  {source}: {count}")
        
        if show_details and recent:
            console.print(f"\n[bold]Recent Activity:[/]")
            for date, count in recent:
                console.print(f"  {date}: {count} documents")
        
    except Exception as e:
        console.print(f"[red]Error getting progress:[/] {e}")


def _show_embed_progress(show_details: bool):
    """Show embedding progress."""
    try:
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
        with psycopg.connect(db_url) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM doc_chunk")
                total_chunks = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM doc_chunk WHERE embedding IS NOT NULL")
                embedded_chunks = cur.fetchone()[0]
                
                if show_details:
                    cur.execute("""
                        SELECT model_name, COUNT(*) as count 
                        FROM doc_chunk 
                        WHERE embedding IS NOT NULL 
                        GROUP BY model_name
                    """)
                    models = cur.fetchall()
        
        progress_pct = (embedded_chunks / total_chunks * 100) if total_chunks > 0 else 0
        console.print(f"[bold]Total Chunks:[/] {total_chunks}")
        console.print(f"[bold]Embedded:[/] {embedded_chunks}")
        console.print(f"[bold]Progress:[/] {progress_pct:.1f}%")
        
        if show_details and models:
            console.print(f"\n[bold]By Model:[/]")
            for model, count in models:
                console.print(f"  {model}: {count}")
        
    except Exception as e:
        console.print(f"[red]Error getting progress:[/] {e}")


def _show_index_progress(show_details: bool):
    """Show indexing progress."""
    index_path = Path("./faiss_index")
    
    if not index_path.exists():
        console.print("[yellow]FAISS index not built yet[/]")
        return
    
    try:
        # This would be enhanced with actual FAISS index statistics
        console.print(f"[bold]Index Location:[/] {index_path}")
        console.print(f"[bold]Status:[/] Built")
        
        if show_details:
            console.print(f"[yellow]Detailed index statistics not yet implemented[/]")
        
    except Exception as e:
        console.print(f"[red]Error getting index progress:[/] {e}")


def _show_analyze_progress(show_details: bool):
    """Show analysis progress."""
    reports_dir = Path("./reports")
    
    if not reports_dir.exists():
        console.print("[yellow]No reports directory found[/]")
        return
    
    try:
        report_files = list(reports_dir.glob("*.md"))
        evidence_files = list(reports_dir.glob("*.jsonl"))
        validation_files = list(reports_dir.glob("validation_*.md"))
        
        console.print(f"[bold]Reports Generated:[/] {len(report_files)}")
        console.print(f"[bold]Evidence Packs:[/] {len(evidence_files)}")
        console.print(f"[bold]Validation Reports:[/] {len(validation_files)}")
        
        if show_details and report_files:
            console.print(f"\n[bold]Recent Reports:[/]")
            recent_reports = sorted(report_files, key=lambda x: x.stat().st_mtime, reverse=True)[:5]
            for report in recent_reports:
                mtime = datetime.fromtimestamp(report.stat().st_mtime)
                console.print(f"  {report.name} ({mtime.strftime('%Y-%m-%d %H:%M')})")
        
    except Exception as e:
        console.print(f"[red]Error getting analysis progress:[/] {e}")


@app.command()
def export(
    format: str = typer.Argument(..., help="Export format: stix, json, csv"),
    output_path: str = typer.Option("./export", help="Output directory"),
    filters: Optional[str] = typer.Option(None, help="Filter criteria (JSON)")
):
    """Export data in various formats."""
    console.print(f"[bold]📤 Export: {format.upper()}[/]")
    
    if format.lower() == "stix":
        _export_stix(output_path, filters)
    elif format.lower() == "json":
        _export_json(output_path, filters)
    elif format.lower() == "csv":
        _export_csv(output_path, filters)
    else:
        console.print(f"[red]Error:[/] Unknown format: {format}")
        console.print("Available formats: stix, json, csv")
        raise typer.Exit(1)


def _export_stix(output_path: str, filters: Optional[str]):
    """Export to STIX format."""
    console.print(f"[blue]Exporting to STIX:[/] {output_path}")
    
    try:
        # Parse filters if provided
        filter_dict = {}
        if filters:
            try:
                filter_dict = json.loads(filters)
            except json.JSONDecodeError:
                console.print("[red]Error:[/] Invalid JSON in filters")
                raise typer.Exit(1)
        
        # This would be enhanced with actual STIX export logic
        console.print("[yellow]STIX export not yet implemented[/]")
        
    except Exception as e:
        console.print(f"[red]Error during STIX export:[/] {e}")
        raise typer.Exit(1)


def _export_json(output_path: str, filters: Optional[str]):
    """Export to JSON format."""
    console.print(f"[blue]Exporting to JSON:[/] {output_path}")
    
    try:
        # Parse filters if provided
        filter_dict = {}
        if filters:
            try:
                filter_dict = json.loads(filters)
            except json.JSONDecodeError:
                console.print("[red]Error:[/] Invalid JSON in filters")
                raise typer.Exit(1)
        
        # This would be enhanced with actual JSON export logic
        console.print("[yellow]JSON export not yet implemented[/]")
        
    except Exception as e:
        console.print(f"[red]Error during JSON export:[/] {e}")
        raise typer.Exit(1)


def _export_csv(output_path: str, filters: Optional[str]):
    """Export to CSV format."""
    console.print(f"[blue]Exporting to CSV:[/] {output_path}")
    
    try:
        # Parse filters if provided
        filter_dict = {}
        if filters:
            try:
                filter_dict = json.loads(filters)
            except json.JSONDecodeError:
                console.print("[red]Error:[/] Invalid JSON in filters")
                raise typer.Exit(1)
        
        # This would be enhanced with actual CSV export logic
        console.print("[yellow]CSV export not yet implemented[/]")
        
    except Exception as e:
        console.print(f"[red]Error during CSV export:[/] {e}")
        raise typer.Exit(1)


@app.command()
def watch(
    action: str = typer.Argument(..., help="Action: start, stop, status, add, remove"),
    watch_dir: Optional[str] = typer.Argument(None, help="Directory to watch"),
    name: Optional[str] = typer.Option(None, "--name", help="Watcher name"),
    debounce: float = typer.Option(2.0, "--debounce", help="Debounce time in seconds")
):
    """Manage folder watchers for automatic PDF ingestion."""
    console.print(f"[bold]👁️ Watch Folder Management[/]")
    
    watch_manager = get_watch_folder_manager()
    
    if action == "start":
        _start_watchers(watch_manager)
    elif action == "stop":
        _stop_watchers(watch_manager)
    elif action == "status":
        _show_watcher_status(watch_manager)
    elif action == "add":
        if not watch_dir:
            console.print("[red]Error:[/] Watch directory required for 'add' action")
            raise typer.Exit(1)
        if not name:
            name = f"watcher_{Path(watch_dir).name}"
        _add_watcher(watch_manager, name, watch_dir, debounce)
    elif action == "remove":
        if not name:
            console.print("[red]Error:[/] Watcher name required for 'remove' action")
            raise typer.Exit(1)
        _remove_watcher(watch_manager, name)
    else:
        console.print(f"[red]Error:[/] Unknown action: {action}")
        console.print("Available actions: start, stop, status, add, remove")
        raise typer.Exit(1)


def _start_watchers(watch_manager):
    """Start all watchers and keep them running."""
    try:
        if not watch_manager.list_watchers():
            console.print("[yellow]⚠️  No watchers configured[/]")
            console.print("Use 'argo watch add <dir> --name <name>' to add a watcher first")
            return
        
        console.print("[green]✅ Starting watch folder manager...[/]")
        console.print("[yellow]Note:[/] This will run until you stop it with Ctrl+C")
        console.print("Drop PDF files into watched directories to auto-ingest them")
        
        # Start the watchers
        watch_manager.start()
        
        # Keep the process running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            console.print("\n[yellow]🛑 Stopping watch folder manager...[/]")
            watch_manager.stop()
            console.print("[green]✅ Watch folder manager stopped[/]")
            
    except Exception as e:
        console.print(f"[red]Error starting watchers:[/] {e}")
        raise typer.Exit(1)


def _stop_watchers(watch_manager):
    """Stop all watchers."""
    try:
        watch_manager.stop()
        console.print("[green]✅ All watchers stopped[/]")
    except Exception as e:
        console.print(f"[red]Error stopping watchers:[/] {e}")
        raise typer.Exit(1)


def _show_watcher_status(watch_manager):
    """Show status of all watchers."""
    watchers = watch_manager.list_watchers()
    
    if not watchers:
        console.print("[yellow]No watchers configured[/]")
        return
    
    # Check if actually running
    is_running = watch_manager.is_running()
    
    console.print(f"\n[bold]Active Watchers:[/] {len(watchers)}")
    console.print(f"Status: {'🟢 Running' if is_running else '🔴 Stopped'}")
    
    for watcher_name in watchers:
        watcher = watch_manager.get_watcher(watcher_name)
        if watcher:
            stats = watcher.get_stats()
            console.print(f"\n[blue]Watcher:[/] {watcher_name}")
            console.print(f"  Directory: {watcher.watch_dir}")
            console.print(f"  Files Processed: {stats['files_processed']}")
            console.print(f"  Files Skipped: {stats['files_skipped']}")
            console.print(f"  Files Failed: {stats['files_failed']}")
            console.print(f"  Total Bytes: {stats['total_bytes']:,}")
            console.print(f"  Uptime: {stats['uptime_seconds']:.1f}s")


def _add_watcher(watch_manager, name: str, watch_dir: str, debounce: float):
    """Add a new watcher."""
    try:
        # Get configuration
        db_url = os.getenv("DATABASE_URL", "postgresql://hunter:hunter@localhost:5433/hunter")
        object_store_dir = "./object_store"
        
        # Add watcher
        watch_manager.add_watcher(name, watch_dir, db_url, object_store_dir, debounce)
        
        console.print(f"[green]✅ Added watcher '{name}' for {watch_dir}[/]")
        console.print(f"   [blue]Debounce:[/] {debounce}s")
        console.print(f"   [blue]Database:[/] {db_url}")
        console.print(f"   [blue]Object Store:[/] {object_store_dir}")
        
        # Start if not already running
        if not watch_manager.running:
            console.print("[yellow]Note:[/] Use 'argo watch start' to start watching")
        
    except Exception as e:
        console.print(f"[red]Error adding watcher:[/] {e}")
        raise typer.Exit(1)


def _remove_watcher(watch_manager, name: str):
    """Remove a watcher."""
    try:
        watch_manager.remove_watcher(name)
        console.print(f"[green]✅ Removed watcher '{name}'[/]")
    except Exception as e:
        console.print(f"[red]Error removing watcher:[/] {e}")
        raise typer.Exit(1)


@app.command()
def help_cmd(
    topic: Optional[str] = typer.Argument(None, help="Help topic: main, workflow, config, examples, troubleshooting, api")
):
    """Show comprehensive help for Argo CLI."""
    help_system = get_help_system(console)
    
    if not topic or topic == "main":
        help_system.show_main_help()
    elif topic == "workflow":
        help_system.show_workflow_help()
    elif topic == "config":
        help_system.show_configuration_help()
    elif topic == "examples":
        help_system.show_examples()
    elif topic == "troubleshooting":
        help_system.show_troubleshooting()
    elif topic == "api":
        help_system.show_api_reference()
    elif topic == "interactive":
        help_system.show_interactive_help()
    else:
        console.print(f"[red]Unknown help topic: {topic}[/]")
        console.print("Available topics: main, workflow, config, examples, troubleshooting, api, interactive")
        raise typer.Exit(1)


@app.command()
def workflow(
    action: str = typer.Argument(..., help="Action: list, run, info"),
    workflow_name: Optional[str] = typer.Argument(None, help="Workflow name"),
    context_file: Optional[str] = typer.Option(None, "--context", help="Context file (JSON)")
):
    """Manage and execute Argo workflows."""
    console.print(f"[bold]🔄 Workflow Management[/]")
    
    workflow_manager = get_workflow_manager()
    
    if action == "list":
        _list_workflows(workflow_manager)
    elif action == "run":
        if not workflow_name:
            console.print("[red]Error:[/] Workflow name required for 'run' action")
            raise typer.Exit(1)
        _run_workflow(workflow_manager, workflow_name, context_file)
    elif action == "info":
        if not workflow_name:
            console.print("[red]Error:[/] Workflow name required for 'info' action")
            raise typer.Exit(1)
        _show_workflow_info(workflow_manager, workflow_name)
    else:
        console.print(f"[red]Error:[/] Unknown action: {action}")
        console.print("Available actions: list, run, info")
        raise typer.Exit(1)


def _list_workflows(workflow_manager):
    """List available workflows."""
    workflows = workflow_manager.list_workflows()
    
    if not workflows:
        console.print("[yellow]No workflows available[/]")
        return
    
    console.print(f"\n[bold]Available Workflows:[/]")
    for workflow_name in workflows:
        workflow = workflow_manager.get_workflow(workflow_name)
        if workflow:
            console.print(f"  [blue]{workflow_name}[/] - {workflow.description}")


def _run_workflow(workflow_manager, workflow_name: str, context_file: Optional[str]):
    """Run a workflow."""
    workflow = workflow_manager.get_workflow(workflow_name)
    if not workflow:
        console.print(f"[red]Error:[/] Workflow '{workflow_name}' not found")
        raise typer.Exit(1)
    
    # Load context if provided
    context = {}
    if context_file:
        try:
            with open(context_file, 'r') as f:
                context = json.load(f)
            console.print(f"[blue]Loaded context from:[/] {context_file}")
        except Exception as e:
            console.print(f"[red]Error loading context file:[/] {e}")
            raise typer.Exit(1)
    
    # Execute workflow
    success = workflow_manager.execute_workflow(workflow_name, context, console)
    
    if success:
        # Show summary
        summary = workflow.get_summary()
        console.print(f"\n[bold]Workflow Summary:[/]")
        console.print(f"  Status: {summary['status']}")
        console.print(f"  Duration: {summary['duration']:.1f}s")
        console.print(f"  Steps: {summary['completed_steps']}/{summary['total_steps']} completed")
    else:
        console.print(f"\n[red]Workflow execution failed[/]")


def _show_workflow_info(workflow_manager, workflow_name: str):
    """Show detailed workflow information."""
    workflow = workflow_manager.get_workflow(workflow_name)
    if not workflow:
        console.print(f"[red]Error:[/] Workflow '{workflow_name}' not found")
        raise typer.Exit(1)
    
    console.print(f"\n[bold]Workflow: {workflow.name}[/]")
    console.print(f"Description: {workflow.description}")
    console.print(f"Total Steps: {len(workflow.steps)}")
    
    console.print(f"\n[bold]Steps:[/]")
    for i, step in enumerate(workflow.steps, 1):
        required = "Required" if step.required else "Optional"
        console.print(f"  {i}. [blue]{step.name}[/] ({required})")
        if step.description:
            console.print(f"     {step.description}")


if __name__ == "__main__":
    app()
