import typer
import uvicorn

from keystone import __version__
from keystone.app import create_app
from keystone.logging import configure_logging
from keystone.settings import Settings

app = typer.Typer(help="Keystone admin CLI.", no_args_is_help=True, add_completion=False)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Address to bind."),
    port: int = typer.Option(8080, help="Port to listen on."),
) -> None:
    """Run the gateway."""
    settings = Settings()
    configure_logging(settings.log_level)
    uvicorn.run(create_app(settings), host=host, port=port)


@app.command()
def version() -> None:
    """Print the package version."""
    typer.echo(f"keystone {__version__}")
