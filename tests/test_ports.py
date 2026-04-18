"""Tests for netscan.ports: TCP port scanning."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from netscan.ports import PortResult, scan_port, scan_ports


class TestScanPort:
    async def test_open_port(self) -> None:
        sem = asyncio.Semaphore(10)
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (AsyncMock(), mock_writer)
            result = await scan_port("127.0.0.1", 80, timeout=1.0, semaphore=sem)

        assert result.port == 80
        assert result.state == "open"

    async def test_closed_port(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await scan_port("127.0.0.1", 8888, timeout=1.0, semaphore=sem)

        assert result.port == 8888
        assert result.state == "closed"

    async def test_filtered_port_timeout(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError):
            result = await scan_port("192.0.2.1", 9999, timeout=0.01, semaphore=sem)

        assert result.port == 9999
        assert result.state == "filtered"

    async def test_filtered_port_os_error(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=OSError("Network unreachable")):
            result = await scan_port("192.0.2.1", 443, timeout=1.0, semaphore=sem)

        assert result.state == "filtered"

    async def test_result_has_correct_structure(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await scan_port("127.0.0.1", 22, timeout=1.0, semaphore=sem)

        assert isinstance(result, PortResult)
        assert result.port == 22
        assert result.service == ""
        assert result.banner == ""
        assert result.version == ""


class TestScanPorts:
    async def test_returns_sorted_results(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            results = await scan_ports("127.0.0.1", [443, 22, 80], timeout=1.0, semaphore=sem)

        ports = [r.port for r in results]
        assert ports == sorted(ports)

    async def test_all_ports_returned(self) -> None:
        sem = asyncio.Semaphore(10)
        test_ports = [22, 80, 443, 8080]

        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            results = await scan_ports("127.0.0.1", test_ports, timeout=1.0, semaphore=sem)

        assert len(results) == len(test_ports)
        assert {r.port for r in results} == set(test_ports)

    async def test_progress_callback_called(self) -> None:
        sem = asyncio.Semaphore(10)
        called_with: list[PortResult] = []

        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            await scan_ports(
                "127.0.0.1",
                [80, 443],
                timeout=1.0,
                semaphore=sem,
                progress_callback=called_with.append,
            )

        assert len(called_with) == 2

    async def test_empty_port_list(self) -> None:
        sem = asyncio.Semaphore(10)
        results = await scan_ports("127.0.0.1", [], timeout=1.0, semaphore=sem)
        assert results == []
