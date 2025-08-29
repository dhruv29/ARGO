import typer
from rich.console import Console

app = typer.Typer(help="Argo CLI — The Argonauts SOC Platform")
console = Console()

@app.command()
def ingest(path: str):
"""Ingest PDFs from a file or directory."""
console.print(f"[bold]Ingest[/] -> {path} (stub)")

@app.command()
def run(agent: str, actor: str = typer.Option(None, help="Actor/Group name"),
exposure: bool = typer.Option(False, "--exposure", help="Include exposure view")):
"""Run an agent (e.g., orpheus)."""
console.print(f"[bold]Run[/] -> agent={agent} actor={actor} exposure={exposure} (stub)")

@app.command()
def status():
"""Show system status."""
console.print("Status (stub)")

if name == "main":
app()
