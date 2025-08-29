import typer
from rich.console import Console
from rich.prompt import Confirm
from argo.runbooks.orpheus_graph import build_orpheus_graph, OrpheusState

app = typer.Typer(help="Argo CLI — The Argonauts SOC Platform")
console = Console()

@app.command()
def ingest(path: str):
    console.print(f"[bold]Ingest[/] -> {path} (stub)")

def _approver(state: OrpheusState) -> bool:
    console.rule("[bold yellow]Orpheus: Approval Gate")
    actor = state.get("actor", "(unknown)")
    ev_count = len(state.get("evidence") or [])
    console.print(f"[bold]Actor:[/] {actor} | [bold]Evidence chunks:[/] {ev_count}")
    # In future: show draft path preview once implemented
    return Confirm.ask("Publish report & evidence now?", default=False)

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
def status():
    console.print("Status (stub)")

if __name__ == "__main__":
    app()
