"""Tests for netscan.discovery: host-reachability detection."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from netscan.discovery import _tcp_probe, check_host


class TestTcpProbe:
    async def test_returns_true_on_successful_connect(self) -> None:
        sem = asyncio.Semaphore(10)
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (AsyncMock(), mock_writer)
            result = await _tcp_probe("127.0.0.1", 80, 1.0, sem)

        assert result is True

    async def test_returns_false_on_connection_refused(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await _tcp_probe("127.0.0.1", 80, 1.0, sem)

        assert result is False

    async def test_returns_false_on_timeout(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch(
            "asyncio.open_connection",
            side_effect=asyncio.TimeoutError,
        ):
            result = await _tcp_probe("127.0.0.1", 80, 0.01, sem)

        assert result is False

    async def test_returns_false_on_os_error(self) -> None:
        sem = asyncio.Semaphore(10)
        with patch("asyncio.open_connection", side_effect=OSError("unreachable")):
            result = await _tcp_probe("192.0.2.1", 80, 1.0, sem)

        assert result is False


class TestCheckHost:
    async def test_host_up_when_any_port_responds(self) -> None:
        mock_writer = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("netscan.discovery._tcp_probe", new_callable=AsyncMock) as mock_probe:
            # First probe succeeds, rest don't matter
            mock_probe.return_value = True
            result = await check_host("192.168.1.1", timeout=1.0)

        assert result is True

    async def test_host_down_when_no_ports_respond(self) -> None:
        with patch("netscan.discovery._tcp_probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = False
            result = await check_host("192.0.2.1", timeout=0.1)

        assert result is False

    async def test_uses_provided_semaphore(self) -> None:
        sem = asyncio.Semaphore(5)
        with patch("netscan.discovery._tcp_probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = True
            await check_host("10.0.0.1", timeout=1.0, semaphore=sem)

        mock_probe.assert_called()

    async def test_creates_default_semaphore_when_none_provided(self) -> None:
        with patch("netscan.discovery._tcp_probe", new_callable=AsyncMock) as mock_probe:
            mock_probe.return_value = False
            # Should not raise even without explicit semaphore
            result = await check_host("10.0.0.1", timeout=0.1)

        assert result is False
