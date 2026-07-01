"""Unit tests for StatusController."""

import sys
from unittest.mock import MagicMock, patch

import pytest
from rich.table import Table

from src.controllers.status_controller import StatusController


@pytest.mark.unit
class TestStatusController:
    def test_get_status_returns_rich_table(self) -> None:
        ctrl = StatusController()
        result = ctrl.get_status()
        assert isinstance(result, Table)

    def test_table_has_component_column(self) -> None:
        ctrl = StatusController()
        result = ctrl.get_status()
        column_names = [col.header for col in result.columns]
        assert "Component" in column_names

    def test_table_has_status_column(self) -> None:
        ctrl = StatusController()
        result = ctrl.get_status()
        column_names = [col.header for col in result.columns]
        assert "Status" in column_names

    def test_table_has_rows(self) -> None:
        ctrl = StatusController()
        result = ctrl.get_status()
        assert result.row_count > 0

    def test_table_title_contains_pqhe(self) -> None:
        ctrl = StatusController()
        result = ctrl.get_status()
        assert "PQ-HE" in (result.title or "")

    def test_python_version_row_present(self) -> None:
        ctrl = StatusController()
        result = ctrl.get_status()
        # Row count includes: Python + 5 packages + 2 KEM rows = 8 minimum
        assert result.row_count >= 8

    def test_kem_status_pyoqs_missing(self) -> None:
        ctrl = StatusController()
        label, status_text, detail = ctrl._kem_status("Kyber768")
        # When pyoqs not installed, status should indicate missing
        assert "missing" in str(status_text).lower() or "pyoqs" in detail.lower()

    def test_kem_status_returns_tuple_of_three(self) -> None:
        ctrl = StatusController()
        result = ctrl._kem_status("ML-KEM-768")
        assert len(result) == 3

    def test_kem_status_when_oqs_available_and_kem_enabled(self) -> None:
        mock_oqs = MagicMock()
        mock_oqs.get_enabled_KEM_mechanisms.return_value = ["Kyber768", "ML-KEM-768"]

        ctrl = StatusController()
        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            label, status_text, detail = ctrl._kem_status("Kyber768")

        assert "Kyber768" in label
        assert "available" in str(status_text).lower()

    def test_kem_status_when_oqs_available_but_kem_not_in_build(self) -> None:
        mock_oqs = MagicMock()
        mock_oqs.get_enabled_KEM_mechanisms.return_value = []  # empty build

        ctrl = StatusController()
        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            label, status_text, detail = ctrl._kem_status("Kyber768")

        assert "unavailable" in str(status_text).lower() or "not in" in detail.lower()
