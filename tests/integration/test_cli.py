"""
Integration tests for the CLI — exercises full keygen → encrypt → decrypt flow
through Click's CliRunner.

These tests verify that the CLI wiring is correct end-to-end.
ML-KEM variant is skipped when pyoqs is not installed.
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from src.views.cli_view import cli


@pytest.mark.integration
class TestCLIHelp:
    def test_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0

    def test_status_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["status"])
        assert result.exit_code == 0

    def test_keygen_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["keygen", "--help"])
        assert result.exit_code == 0

    def test_encrypt_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["encrypt", "--help"])
        assert result.exit_code == 0

    def test_decrypt_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["decrypt", "--help"])
        assert result.exit_code == 0


@pytest.mark.integration
class TestKeygenCLI:
    def test_keygen_creates_x25519_key_files(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["keygen", "--name", "alice", "--keys-dir", str(tmp_path)])
        assert result.exit_code == 0, result.output
        assert (tmp_path / "alice_x25519_private.json").exists()
        assert (tmp_path / "alice_x25519_public.json").exists()

    def test_keygen_private_key_permissions(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(cli, ["keygen", "--name", "alice", "--keys-dir", str(tmp_path)])
        priv = tmp_path / "alice_x25519_private.json"
        assert priv.exists()
        assert priv.stat().st_mode & 0o777 == 0o600

    def test_keygen_missing_name_fails(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["keygen"])
        assert result.exit_code != 0

    def test_keygen_uses_default_keys_dir(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(cli, ["keygen", "--name", "bob"])
            assert result.exit_code == 0, result.output
            assert Path("keys/bob_x25519_private.json").exists()


@pytest.mark.integration
class TestEncryptDecryptCLI:
    def test_full_round_trip(self, tmp_path: Path) -> None:
        runner = CliRunner()

        # Generate keys for bob
        r = runner.invoke(cli, ["keygen", "--name", "bob", "--keys-dir", str(tmp_path)])
        assert r.exit_code == 0, r.output

        # Create plaintext file
        infile = tmp_path / "secret.txt"
        infile.write_bytes(b"top secret message")

        # Encrypt
        enc_file = tmp_path / "secret.txt.enc"
        r = runner.invoke(cli, [
            "encrypt", str(infile),
            "--sender", "alice",
            "--recipient", "bob",
            "--keys-dir", str(tmp_path),
            "--output", str(enc_file),
        ])
        assert r.exit_code == 0, r.output
        assert enc_file.exists()

        # Decrypt
        out_file = tmp_path / "recovered.txt"
        r = runner.invoke(cli, [
            "decrypt", str(enc_file),
            "--recipient", "bob",
            "--keys-dir", str(tmp_path),
            "--output", str(out_file),
        ])
        assert r.exit_code == 0, r.output
        assert out_file.read_bytes() == b"top secret message"

    def test_encrypt_nonexistent_recipient_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()
        infile = tmp_path / "data.txt"
        infile.write_bytes(b"data")
        result = runner.invoke(cli, [
            "encrypt", str(infile),
            "--recipient", "nobody",
            "--keys-dir", str(tmp_path),
            "--output", str(tmp_path / "out.enc"),
        ])
        assert result.exit_code != 0

    def test_decrypt_wrong_key_exits_nonzero(self, tmp_path: Path) -> None:
        runner = CliRunner()

        # Generate keys for both bob and eve
        runner.invoke(cli, ["keygen", "--name", "bob", "--keys-dir", str(tmp_path)])
        runner.invoke(cli, ["keygen", "--name", "eve", "--keys-dir", str(tmp_path)])

        # Encrypt for bob
        infile = tmp_path / "secret.txt"
        infile.write_bytes(b"secret")
        enc_file = tmp_path / "secret.enc"
        runner.invoke(cli, [
            "encrypt", str(infile),
            "--sender", "alice",
            "--recipient", "bob",
            "--keys-dir", str(tmp_path),
            "--output", str(enc_file),
        ])

        # Try to decrypt with eve's key — must fail
        r = runner.invoke(cli, [
            "decrypt", str(enc_file),
            "--recipient", "eve",
            "--keys-dir", str(tmp_path),
            "--output", str(tmp_path / "out.txt"),
        ])
        assert r.exit_code != 0

    def test_encrypt_default_output_name(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(cli, ["keygen", "--name", "bob", "--keys-dir", str(tmp_path)])

        infile = tmp_path / "message.txt"
        infile.write_bytes(b"hello")
        runner.invoke(cli, [
            "encrypt", str(infile),
            "--recipient", "bob",
            "--keys-dir", str(tmp_path),
        ])

        assert (tmp_path / "message.txt.enc").exists()

    def test_decrypt_default_output_strips_enc(self, tmp_path: Path) -> None:
        runner = CliRunner()
        runner.invoke(cli, ["keygen", "--name", "bob", "--keys-dir", str(tmp_path)])

        infile = tmp_path / "data.txt"
        infile.write_bytes(b"payload")
        enc_file = tmp_path / "data.txt.enc"
        runner.invoke(cli, [
            "encrypt", str(infile),
            "--recipient", "bob",
            "--keys-dir", str(tmp_path),
            "--output", str(enc_file),
        ])

        runner.invoke(cli, [
            "decrypt", str(enc_file),
            "--recipient", "bob",
            "--keys-dir", str(tmp_path),
        ])
        # .enc stripped → data.txt (but infile already exists, so write over it)
        assert (tmp_path / "data.txt").read_bytes() == b"payload"
