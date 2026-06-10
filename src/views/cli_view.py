"""
CLI view — the only file allowed to render terminal output.

Wires Click commands to controllers. No cryptographic logic lives here.
Rich is used exclusively for display; business results come from controllers.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console(stderr=False)

BANNER = """
██████╗  ██████╗       ██╗  ██╗███████╗
██╔══██╗██╔═══██╗      ██║  ██║██╔════╝
██████╔╝██║   ██║█████╗███████║█████╗
██╔═══╝ ██║▄▄ ██║╚════╝██╔══██║██╔══╝
██║     ╚██████╔╝      ██║  ██║███████╗
╚═╝      ╚══▀▀═╝       ╚═╝  ╚═╝╚══════╝
Post-Quantum Hybrid Encrypter  v1.0.0
"""


def _print_banner() -> None:
    console.print(
        Panel(
            Text(BANNER, style="bold cyan", justify="center"),
            border_style="bright_blue",
            padding=(0, 2),
        )
    )


@click.group()
@click.version_option("1.0.0", prog_name="pqhe")
def cli() -> None:
    """PQ-HE: Post-Quantum Hybrid Encrypter.

    Combines X25519 + ML-KEM-768 key exchange with AES-256-GCM encryption.
    """
    _print_banner()


@cli.command("status")
def status_cmd() -> None:
    """Show system status and algorithm availability."""
    from src.controllers.status_controller import StatusController  # noqa: PLC0415

    controller = StatusController()
    result = controller.get_status()
    console.print(result)


@cli.command("keygen")
@click.option("--name", "-n", required=True, help="Key-pair identifier (e.g. alice).")
@click.option(
    "--output-dir",
    "-o",
    default="./keys",
    show_default=True,
    help="Directory to write key files.",
)
def keygen_cmd(name: str, output_dir: str) -> None:
    """Generate a hybrid X25519 + ML-KEM-768 key pair."""
    console.print(f"[bold green]Generating hybrid key pair:[/] [cyan]{name}[/]")


@cli.command("encrypt")
@click.argument("plaintext_file", type=click.Path(exists=True, readable=True))
@click.option("--recipient-key", "-r", required=True, help="Recipient public-key file.")
@click.option("--output", "-o", default=None, help="Output ciphertext file (default: <input>.enc).")
def encrypt_cmd(plaintext_file: str, recipient_key: str, output: str | None) -> None:
    """Encrypt a file for a recipient using hybrid PQ encryption."""
    console.print(f"[bold yellow]Encrypting:[/] [cyan]{plaintext_file}[/]")


@cli.command("decrypt")
@click.argument("ciphertext_file", type=click.Path(exists=True, readable=True))
@click.option("--private-key", "-k", required=True, help="Recipient private-key file.")
@click.option("--output", "-o", default=None, help="Output plaintext file.")
def decrypt_cmd(ciphertext_file: str, private_key: str, output: str | None) -> None:
    """Decrypt a hybrid-encrypted file using a private key."""
    console.print(f"[bold magenta]Decrypting:[/] [cyan]{ciphertext_file}[/]")
