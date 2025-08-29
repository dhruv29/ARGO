import typer
from rich.console import Console

app = typer.Typer(help="Argo CLI — The Argonauts SOC Platform")
console = Console()

@app.command()
def ingest(path: str):
    console.print(f"[bold]Ingest[/] -> {path} (stub)")

@app.command()
def run(agent: str, actor: str = typer.Option(None), exposure: bool = False):
    console.print(f"[bold]Run[/] -> agent={agent} actor={actor} exposure={exposure} (stub)")

@app.command()
def status():
    console.print("Status (stub)")

if __name__ == "__main__":
    app()
