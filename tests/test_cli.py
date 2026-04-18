"""Tests for netscan.cli: Typer CLI integration."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from netscan.cli import app
from netscan.ports import PortResult
from netscan.scanner import ScanResult

runner = CliRunner()


def _make_result(ip: str = "10.0.0.1", is_up: bool = True) -> ScanResult:
    result = ScanResult(ip=ip, is_up=is_up)
    result.open_ports = [PortResult(port=22, state="open", service="SSH", version="OpenSSH 8.9")]
    result.scan_duration = 0.5
    return result


class TestCliBasic:
    def test_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "Target" in result.output or "netscan" in result.output

    def test_version_exits_zero(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_invalid_target_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["this.host.definitely.does.not.exist.invalid"])
        assert result.exit_code != 0

    def test_invalid_export_format_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["127.0.0.1", "--export", "pdf"])
        assert result.exit_code == 2

    def test_invalid_port_spec_exits_nonzero(self) -> None:
        result = runner.invoke(app, ["127.0.0.1", "-p", "notaport"])
        assert result.exit_code == 2


class TestCliScan:
    def test_scan_runs_and_exits_zero(self) -> None:
        mock_results = [_make_result()]

        with patch("netscan.cli.Scanner") as MockScanner:
            instance = MockScanner.return_value
            instance.scan = AsyncMock(return_value=mock_results)

            result = runner.invoke(app, ["127.0.0.1", "-p", "80", "--no-discovery", "-q"])

        assert result.exit_code == 0

    def test_quiet_flag_suppresses_banner(self) -> None:
        mock_results = [_make_result(is_up=False)]

        with patch("netscan.cli.Scanner") as MockScanner:
            instance = MockScanner.return_value
            instance.scan = AsyncMock(return_value=mock_results)

            result = runner.invoke(app, ["127.0.0.1", "-p", "80", "--no-discovery", "-q"])

        # Quiet mode should not print the netscan banner header
        assert "netscan" not in result.output or result.output.strip() == ""

    def test_export_json_creates_file(self, tmp_path: Path) -> None:
        out_file = str(tmp_path / "test.json")
        mock_results = [_make_result()]

        with patch("netscan.cli.Scanner") as MockScanner:
            instance = MockScanner.return_value
            instance.scan = AsyncMock(return_value=mock_results)

            result = runner.invoke(
                app,
                ["127.0.0.1", "-p", "80", "--no-discovery", "-q", "--export", "json", "-o", out_file],
            )

        assert result.exit_code == 0
        assert Path(out_file).exists()
        data = json.loads(Path(out_file).read_text())
        assert "hosts" in data

    def test_no_discovery_flag_passed_to_config(self) -> None:
        mock_results: list[ScanResult] = []
        captured_config: list = []

        with patch("netscan.cli.Scanner") as MockScanner:
            def capture_init(config):  # noqa: ANN001, ANN202
                captured_config.append(config)
                instance = MagicMock()
                instance.scan = AsyncMock(return_value=mock_results)
                return instance

            MockScanner.side_effect = capture_init
            runner.invoke(app, ["127.0.0.1", "-p", "80", "--no-discovery", "-q"])

        assert len(captured_config) == 1
        assert captured_config[0].host_discovery is False

    def test_concurrency_option(self) -> None:
        captured_config: list = []

        with patch("netscan.cli.Scanner") as MockScanner:
            def capture_init(config):  # noqa: ANN001, ANN202
                captured_config.append(config)
                instance = MagicMock()
                instance.scan = AsyncMock(return_value=[])
                return instance

            MockScanner.side_effect = capture_init
            runner.invoke(app, ["127.0.0.1", "-p", "80", "-c", "50", "--no-discovery", "-q"])

        assert captured_config[0].concurrency == 50
