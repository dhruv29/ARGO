import os
from pathlib import Path
import typer
from rich.console import Console
from rich.prompt import Confirm
from argo.runbooks.orpheus_graph import build_orpheus_graph, OrpheusState
from argo.core.ingest import ingest_directory
from argo.core.embed import embed_all_chunks, get_embedding_stats
from argo.core.faiss_index import build_faiss_index
from argo.core.retrieve import retrieve

app = typer.Typer(help="Argo CLI — The Argonauts SOC Platform")
console = Console()

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
    console.rule("[bold yellow]🔍 Orpheus: Approval Gate")
    
    actor = state.get("actor", "(unknown)")
    aliases = state.get("aliases", [])
    ttps = state.get("ttps", [])
    cves = state.get("cves", [])
    evidence = state.get("evidence", [])
    draft_report = state.get("draft_report", "")
    plan = state.get("plan", {})
    
    # Actor Information
    console.print(f"[bold blue]🎯 Target Actor:[/] {actor}")
    if aliases:
        console.print(f"[bold blue]📋 Aliases:[/] {', '.join(aliases[:5])}")
        if len(aliases) > 5:
            console.print(f"   ... and {len(aliases) - 5} more")
    
    # Expansion Results
    console.print()
    console.print(f"[bold green]🔧 TTPs Found:[/] {len(ttps)}")
    if ttps:
        console.print(f"   {', '.join(ttps[:5])}")
        if len(ttps) > 5:
            console.print(f"   ... and {len(ttps) - 5} more")
    
    console.print(f"[bold green]🚨 CVEs Found:[/] {len(cves)}")
    if cves:
        console.print(f"   {', '.join(cves[:5])}")
        if len(cves) > 5:
            console.print(f"   ... and {len(cves) - 5} more")
    
    # Evidence Statistics
    console.print()
    console.print(f"[bold cyan]📊 Evidence Statistics:[/]")
    console.print(f"   Total Chunks: {len(evidence)}")
    
    if evidence:
        # Evidence by source
        sources = {}
        docs = set()
        high_conf = 0
        
        for ev in evidence:
            source = ev.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1
            docs.add(ev.get('document_id', 'unknown'))
            if ev.get('score', 0) > 0.8:
                high_conf += 1
        
        console.print(f"   Documents: {len(docs)}")
        console.print(f"   High Confidence (>0.8): {high_conf}")
        console.print(f"   Sources: {dict(sources)}")
        
        # Evidence quality distribution
        scores = [ev.get('score', 0) for ev in evidence]
        avg_score = sum(scores) / len(scores) if scores else 0
        console.print(f"   Average Score: {avg_score:.3f}")
    
    # Search Plan
    console.print()
    console.print(f"[bold magenta]🔍 Search Plan:[/]")
    search_terms = plan.get('search_terms', [])
    namespaces = plan.get('namespaces', [])
    console.print(f"   Terms: {', '.join(search_terms[:5])}")
    if len(search_terms) > 5:
        console.print(f"   ... and {len(search_terms) - 5} more")
    console.print(f"   Namespaces: {', '.join(namespaces)}")
    
    # Draft Report Preview
    console.print()
    console.print(f"[bold yellow]📄 Draft Report:[/]")
    console.print(f"   Length: {len(draft_report)} characters")
    
    if draft_report:
        # Show first few lines of the report
        lines = draft_report.split('\\n')[:5]
        for line in lines:
            if line.strip():
                console.print(f"   {line[:80]}...")
                break
    
    # Alias candidates from RAG-LLM fallback
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
        write_approved = Confirm.ask("💾 Approve writing these aliases to the knowledge graph?", default=False)
        state["approved_alias_write"] = write_approved
        
        if write_approved:
            console.print("[green]✅ Alias write approved[/]")
        else:
            console.print("[yellow]⚠️  Alias write declined - aliases will not be saved[/]")
    
    # Vision Usage (placeholder for future implementation)  
    console.print()
    console.print(f"[bold red]👁️  Vision Usage:[/] Not implemented yet")
    
    # Draft Paths
    console.print()
    console.print(f"[bold white]📁 Output Paths:[/]")
    console.print(f"   Report: reports/report_orpheus_{actor}_[timestamp].md")
    console.print(f"   Evidence: reports/evidence_orpheus_{actor}_[timestamp].jsonl")
    
    console.print()
    return Confirm.ask("🚀 Publish report & evidence now?", default=False)

@app.command()
def run(
    agent: str,
    actor: str = typer.Option(None, help="Actor/Group name"),
    exposure: bool = typer.Option(False, "--exposure", help="Include exposure view")
):
    if agent.lower() != "orpheus":
        console.print(f"[red]Unsupported agent:[/] {agent} (only 'orpheus' for now)")
        raise typer.Exit(2)

    graph = build_orpheus_graph(approver=_approver)
    initial: OrpheusState = {"run_id": "local-run", "actor": actor or ""}

    # LangGraph runnable interface
    final_state: OrpheusState = graph.invoke(initial)
    if final_state.get("approved"):
        out = final_state.get("outputs", {})
        console.print(f"[green]Published[/] -> {out}")
    else:
        console.print("[yellow]Draft not approved; nothing published.[/]")
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
def search(
    query: str,
    limit: int = typer.Option(15, help="Maximum number of results"),
    namespace: str = typer.Option("personal", help="Namespace to search in")
):
    """Search for documents using hybrid retrieval (FAISS + BM25)."""
    try:
        console.print(f"[bold]Searching for:[/] '{query}'")
        console.print(f"[bold]Namespace:[/] {namespace}")
        console.print(f"[bold]Limit:[/] {limit}")
        console.print()
        
        with console.status("[bold green]Searching..."):
            results = retrieve(query, namespaces=(namespace,), topk=limit)
        
        if not results:
            console.print("[yellow]No results found.[/]")
            return
        
        console.print(f"[green]Found {len(results)} results:[/]")
        console.print()
        
        for i, evidence in enumerate(results, 1):
            console.print(f"[bold]{i}. Document {evidence.document_id} (Page {evidence.page})[/]")
            console.print(f"   [blue]Source:[/] {evidence.source}")
            console.print(f"   [blue]Score:[/] {evidence.score:.3f}")
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
