"""
CLI view — the only file allowed to render terminal output.

Wires Click commands to controllers. No cryptographic logic lives here.
Rich is used exclusively for display; business results come from controllers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
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


def _error(msg: str) -> None:
    console.print(Panel(f"[bold red]Error:[/] {msg}", border_style="red", title="[bold red]Failed[/]"))


def _success(msg: str) -> None:
    console.print(Panel(f"[bold green]{msg}[/]", border_style="green", title="[bold green]Done[/]"))


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


@click.group()
@click.version_option("1.0.0", prog_name="pqhe")
def cli() -> None:
    """PQ-HE: Post-Quantum Hybrid Encrypter.

    Combines X25519 + ML-KEM-768 key exchange with AES-256-GCM encryption.
    """
    _print_banner()


# ------------------------------------------------------------------
# status
# ------------------------------------------------------------------

@cli.command("status")
def status_cmd() -> None:
    """Show system status and algorithm availability."""
    from src.controllers.status_controller import StatusController  # noqa: PLC0415

    controller = StatusController()
    result = controller.get_status()
    console.print(result)


# ------------------------------------------------------------------
# keygen
# ------------------------------------------------------------------

@cli.command("keygen")
@click.option("--name", "-n", required=True, help="Key-pair identifier (e.g. alice).")
@click.option(
    "--keys-dir",
    "-d",
    default="./keys",
    show_default=True,
    help="Directory to write key files.",
)
def keygen_cmd(name: str, keys_dir: str) -> None:
    """Generate a hybrid X25519 + ML-KEM-768 key pair."""
    from src.controllers.keygen_controller import KeygenController  # noqa: PLC0415

    from src.utils.validators import ValidationError  # noqa: PLC0415

    controller = KeygenController()
    try:
        result = controller.generate(key_id=name, keys_dir=Path(keys_dir))
    except (ValueError, ValidationError) as exc:
        _error(str(exc))
        sys.exit(1)

    table = Table(title=f"Key Pair — [bold cyan]{result.key_id}[/]", border_style="bright_blue", show_lines=True)
    table.add_column("File", style="cyan", min_width=32)
    table.add_column("Type", min_width=22)
    table.add_column("Permissions", min_width=12)

    table.add_row(
        str(result.x25519_private_path),
        "X25519 private key",
        Text("0600 (owner only)", style="bold yellow"),
    )
    table.add_row(
        str(result.x25519_public_path),
        "X25519 public key",
        "0644",
    )

    if result.mlkem_available and result.mlkem_private_path and result.mlkem_public_path:
        table.add_row(
            str(result.mlkem_private_path),
            "ML-KEM-768 private key",
            Text("0600 (owner only)", style="bold yellow"),
        )
        table.add_row(
            str(result.mlkem_public_path),
            "ML-KEM-768 public key",
            "0644",
        )
    else:
        table.add_row(
            Text("(skipped — pyoqs not installed)", style="dim"),
            "ML-KEM-768 keys",
            "—",
        )

    console.print(table)

    mode_label = (
        Text("Hybrid (X25519 + ML-KEM-768)", style="bold green")
        if result.mlkem_available
        else Text("Classical (X25519 only)", style="yellow")
    )
    console.print(f"  Mode: {mode_label}")
    console.print(f"  Share [bold cyan]{result.x25519_public_path.name}[/] (and [bold cyan]{result.mlkem_public_path.name if result.mlkem_public_path else 'N/A'}[/]) with anyone who wants to encrypt for [bold]{result.key_id}[/].")


# ------------------------------------------------------------------
# encrypt
# ------------------------------------------------------------------

@cli.command("encrypt")
@click.argument("plaintext_file", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option("--sender", "-s", default="anonymous", show_default=True, help="Sender label (bound into packet metadata).")
@click.option("--recipient", "-r", required=True, help="Recipient key ID (e.g. bob).")
@click.option(
    "--keys-dir",
    "-d",
    default="./keys",
    show_default=True,
    help="Directory containing recipient public keys.",
)
@click.option("--output", "-o", default=None, help="Output file (default: <input>.enc).")
def encrypt_cmd(
    plaintext_file: Path,
    sender: str,
    recipient: str,
    keys_dir: str,
    output: str | None,
) -> None:
    """Encrypt a file for a recipient using hybrid PQ encryption."""
    from src.controllers.encrypt_controller import EncryptController  # noqa: PLC0415

    out_path = (
        Path(output)
        if output
        else plaintext_file.with_name(plaintext_file.name + ".enc")
    )

    from src.utils.validators import ValidationError  # noqa: PLC0415

    controller = EncryptController()
    try:
        result = controller.encrypt_file(
            input_path=plaintext_file,
            output_path=out_path,
            sender_key_id=sender,
            recipient_key_id=recipient,
            keys_dir=Path(keys_dir),
        )
    except (FileNotFoundError, ValidationError) as exc:
        _error(str(exc))
        sys.exit(1)
    except Exception as exc:
        _error(f"Encryption failed: {exc}")
        sys.exit(1)

    table = Table(title="Encryption complete", border_style="green", show_lines=True)
    table.add_column("Field", style="bold cyan", min_width=18)
    table.add_column("Value", min_width=40)

    table.add_row("Input", str(result.input_path))
    table.add_row("Output", str(result.output_path))
    table.add_row("Sender", sender)
    table.add_row("Recipient", recipient)
    table.add_row("Algorithm", result.algorithm)
    table.add_row("Mode", Text("Hybrid", style="bold green") if result.is_hybrid else Text("Classical", style="yellow"))
    table.add_row("Plaintext size", _fmt_size(result.plaintext_size))
    table.add_row("Ciphertext size", _fmt_size(result.ciphertext_size))

    console.print(table)


# ------------------------------------------------------------------
# decrypt
# ------------------------------------------------------------------

@cli.command("decrypt")
@click.argument("ciphertext_file", type=click.Path(exists=True, readable=True, path_type=Path))
@click.option("--recipient", "-r", required=True, help="Recipient key ID whose private key is used.")
@click.option(
    "--keys-dir",
    "-d",
    default="./keys",
    show_default=True,
    help="Directory containing recipient private keys.",
)
@click.option("--output", "-o", default=None, help="Output file (default: strips .enc or adds .dec).")
def decrypt_cmd(
    ciphertext_file: Path,
    recipient: str,
    keys_dir: str,
    output: str | None,
) -> None:
    """Decrypt a hybrid-encrypted file using a private key."""
    from src.controllers.decrypt_controller import DecryptController  # noqa: PLC0415
    from src.services.aes_service import AuthenticationError  # noqa: PLC0415

    if output:
        out_path = Path(output)
    elif ciphertext_file.suffix == ".enc":
        out_path = ciphertext_file.with_suffix("")
    else:
        out_path = ciphertext_file.with_name(ciphertext_file.stem + ".dec")

    from src.utils.validators import ValidationError  # noqa: PLC0415

    controller = DecryptController()
    try:
        result = controller.decrypt_file(
            input_path=ciphertext_file,
            output_path=out_path,
            recipient_key_id=recipient,
            keys_dir=Path(keys_dir),
        )
    except (FileNotFoundError, ValidationError) as exc:
        _error(str(exc))
        sys.exit(1)
    except AuthenticationError:
        _error(
            "Authentication failed — the packet may have been tampered with, "
            "or the wrong private key was provided."
        )
        sys.exit(1)
    except Exception as exc:
        _error(f"Decryption failed: {exc}")
        sys.exit(1)

    table = Table(title="Decryption complete", border_style="green", show_lines=True)
    table.add_column("Field", style="bold cyan", min_width=18)
    table.add_column("Value", min_width=40)

    table.add_row("Input", str(result.input_path))
    table.add_row("Output", str(result.output_path))
    table.add_row("Recipient", recipient)
    table.add_row("Algorithm", result.algorithm)
    table.add_row("Plaintext size", _fmt_size(result.plaintext_size))

    console.print(table)
