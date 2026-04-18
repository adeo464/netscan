"""Tests for netscan.scanner: orchestration and ScanResult construction."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from netscan.ports import PortResult
from netscan.scanner import ScanConfig, Scanner, ScanResult


def _default_config(ports: list[int] | None = None) -> ScanConfig:
    return ScanConfig(
        ports=ports or [22, 80, 443],
        timeout=0.5,
        concurrency=10,
        host_discovery=True,
        grab_banners=False,
        os_detection=False,
    )


class TestScanConfig:
    def test_defaults(self) -> None:
        cfg = ScanConfig(ports=[80])
        assert cfg.timeout == 1.0
        assert cfg.concurrency == 100
        assert cfg.grab_banners is True
        assert cfg.os_detection is True
        assert cfg.host_discovery is True
        assert cfg.rate_limit is None

    def test_custom_values(self) -> None:
        cfg = ScanConfig(ports=[22, 80], timeout=2.0, concurrency=50)
        assert cfg.timeout == 2.0
        assert cfg.concurrency == 50


class TestScanResult:
    def test_defaults(self) -> None:
        r = ScanResult(ip="10.0.0.1")
        assert r.is_up is False
        assert r.open_ports == []
        assert r.os_guess is None
        assert r.error is None
        assert r.hostname is None


class TestScanner:
    async def test_scan_returns_one_result_per_target(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock) as mock_disc,
            patch("netscan.scanner.scan_ports", new_callable=AsyncMock) as mock_ports,
            patch("netscan.scanner.detect_services", new_callable=AsyncMock) as mock_svc,
        ):
            mock_disc.return_value = True
            mock_ports.return_value = []
            mock_svc.return_value = []

            results = await scanner.scan(["10.0.0.1", "10.0.0.2"])

        assert len(results) == 2
        assert all(isinstance(r, ScanResult) for r in results)

    async def test_scan_skips_port_scan_for_down_hosts(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock) as mock_disc,
            patch("netscan.scanner.scan_ports", new_callable=AsyncMock) as mock_ports,
        ):
            mock_disc.return_value = False
            mock_ports.return_value = []

            results = await scanner.scan(["192.0.2.1"])

        mock_ports.assert_not_called()
        assert results[0].is_up is False

    async def test_scan_marks_host_up_after_discovery(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock) as mock_disc,
            patch("netscan.scanner.scan_ports", new_callable=AsyncMock) as mock_ports,
        ):
            mock_disc.return_value = True
            mock_ports.return_value = []

            results = await scanner.scan(["10.0.0.1"])

        assert results[0].is_up is True

    async def test_no_discovery_treats_all_hosts_as_up(self) -> None:
        cfg = ScanConfig(
            ports=[80],
            timeout=0.5,
            concurrency=5,
            host_discovery=False,
            grab_banners=False,
            os_detection=False,
        )
        scanner = Scanner(cfg)

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock) as mock_disc,
            patch("netscan.scanner.scan_ports", new_callable=AsyncMock) as mock_ports,
        ):
            mock_ports.return_value = []

            results = await scanner.scan(["10.0.0.1"])

        mock_disc.assert_not_called()
        assert results[0].is_up is True

    async def test_open_ports_appear_in_result(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)
        open_port = PortResult(port=80, state="open")

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock, return_value=True),
            patch(
                "netscan.scanner.scan_ports",
                new_callable=AsyncMock,
                return_value=[open_port],
            ),
        ):
            results = await scanner.scan(["10.0.0.1"])

        assert len(results[0].open_ports) == 1
        assert results[0].open_ports[0].port == 80

    async def test_scan_duration_is_positive(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock, return_value=False),
        ):
            results = await scanner.scan(["10.0.0.1"])

        assert results[0].scan_duration >= 0.0

    async def test_progress_callback_called_for_each_host(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)
        calls: list[tuple[str, int, int]] = []

        with (
            patch("netscan.scanner.check_host", new_callable=AsyncMock, return_value=False),
        ):
            await scanner.scan(
                ["10.0.0.1", "10.0.0.2"],
                progress_callback=lambda ip, done, total: calls.append((ip, done, total)),
            )

        assert len(calls) == 2

    async def test_empty_targets_returns_empty_list(self) -> None:
        cfg = _default_config()
        scanner = Scanner(cfg)
        results = await scanner.scan([])
        assert results == []
