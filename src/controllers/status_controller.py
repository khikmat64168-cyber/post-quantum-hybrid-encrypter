"""
Status controller — gathers system and algorithm availability information.

Calls no cryptographic primitives directly; delegates to services (added in
later phases). Returns Rich renderables consumed by the CLI view.
"""

from __future__ import annotations

import sys
from importlib.metadata import version as pkg_version, PackageNotFoundError

from rich.table import Table
from rich.text import Text

from src.utils.logging_config import get_logger

log = get_logger(__name__)


class StatusController:
    """Orchestrates collection of system-status data for the status command."""

    def get_status(self) -> Table:
        """Return a Rich Table describing runtime and algorithm availability."""
        log.info("status_controller.get_status.called")

        table = Table(title="PQ-HE System Status", border_style="bright_blue", show_lines=True)
        table.add_column("Component", style="bold cyan", min_width=28)
        table.add_column("Status", min_width=20)
        table.add_column("Detail", min_width=36)

        # Python runtime
        py = sys.version_info
        table.add_row(
            "Python Runtime",
            _ok("available"),
            f"{py.major}.{py.minor}.{py.micro}",
        )

        # Dependency versions
        for pkg in ("cryptography", "pyoqs", "rich", "click", "pydantic"):
            try:
                v = pkg_version(pkg)
                table.add_row(pkg, _ok("installed"), v)
            except PackageNotFoundError:
                table.add_row(pkg, _warn("missing"), "run: pip install -r requirements.txt")

        # liboqs KEM availability (pyoqs wraps liboqs)
        table.add_row(*self._kem_status("Kyber768"))
        table.add_row(*self._kem_status("ML-KEM-768"))

        log.info("status_controller.get_status.complete")
        return table

    def _kem_status(self, algorithm: str) -> tuple[str, Text, str]:
        try:
            import oqs  # type: ignore[import-untyped]

            enabled = oqs.get_enabled_KEM_mechanisms()
            if algorithm in enabled:
                return (f"KEM: {algorithm}", _ok("available"), "liboqs")
            return (f"KEM: {algorithm}", _warn("unavailable"), "not in liboqs build")
        except ImportError:
            return (f"KEM: {algorithm}", _warn("missing"), "pyoqs not installed")


def _ok(label: str) -> Text:
    return Text(f"✓ {label}", style="bold green")


def _warn(label: str) -> Text:
    return Text(f"✗ {label}", style="bold red")
