"""Tests for netscan.services: banner grabbing and service detection."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from netscan.ports import PortResult
from netscan.services import (
    _grab_tcp_banner,
    detect_service,
    detect_services,
    grab_banner,
)


class TestDetectService:
    def test_known_port_no_banner(self) -> None:
        name, version = detect_service(22)
        assert name == "SSH"
        assert version == ""

    def test_known_port_with_ssh_banner(self) -> None:
        name, version = detect_service(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")
        assert name == "OpenSSH"
        assert "8.9" in version

    def test_http_apache_banner(self) -> None:
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n"
        name, version = detect_service(80, banner)
        assert name == "Apache httpd"
        assert "2.4.54" in version

    def test_nginx_banner(self) -> None:
        banner = "HTTP/1.1 400 Bad Request\r\nServer: nginx/1.22.1\r\n"
        name, version = detect_service(80, banner)
        assert name == "nginx"
        assert "1.22.1" in version

    def test_iis_banner(self) -> None:
        banner = "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n"
        name, version = detect_service(443, banner)
        assert name == "Microsoft IIS"
        assert "10.0" in version

    def test_ftp_vsftpd_banner(self) -> None:
        name, version = detect_service(21, "220 (vsFTPd 3.0.5)")
        assert name == "vsftpd"
        assert "3.0.5" in version

    def test_smtp_postfix_banner(self) -> None:
        name, version = detect_service(25, "220 mail.example.com ESMTP Postfix")
        assert name == "Postfix SMTP"

    def test_redis_pong_banner(self) -> None:
        name, version = detect_service(6379, "+PONG\r\n")
        assert name == "Redis"

    def test_unknown_port_no_banner(self) -> None:
        name, version = detect_service(19999)
        assert name == "unknown"
        assert version == ""

    def test_empty_banner(self) -> None:
        name, version = detect_service(22, "")
        # Falls back to port-based name
        assert name == "SSH"
        assert version == ""

    def test_dropbear_ssh(self) -> None:
        name, version = detect_service(22, "SSH-2.0-dropbear_2022.83")
        assert name == "Dropbear SSH"
        assert "2022.83" in version


class TestGrabBanner:
    async def test_returns_banner_on_success(self) -> None:
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9\r\n")

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            result = await grab_banner("127.0.0.1", 22, timeout=2.0)

        assert result is not None
        assert "SSH" in result

    async def test_returns_none_on_connection_refused(self) -> None:
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await grab_banner("127.0.0.1", 9999, timeout=1.0)
        assert result is None

    async def test_returns_none_on_timeout(self) -> None:
        with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError):
            result = await grab_banner("192.0.2.1", 80, timeout=0.01)
        assert result is None


class TestGrabTcpBanner:
    async def test_sends_probe_and_reads_response(self) -> None:
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"HTTP/1.1 200 OK\r\nServer: nginx/1.22\r\n")

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            result = await _grab_tcp_banner(
                "127.0.0.1", 80, b"HEAD / HTTP/1.0\r\n\r\n", 2.0
            )

        assert result is not None
        assert "nginx" in result

    async def test_returns_none_when_no_data(self) -> None:
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.wait_closed = AsyncMock()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"")

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (mock_reader, mock_writer)
            result = await _grab_tcp_banner("127.0.0.1", 80, b"", 2.0)

        assert result is None


class TestDetectServices:
    async def test_enriches_port_results(self) -> None:
        port = PortResult(port=22, state="open")

        with patch("netscan.services.grab_banner", new_callable=AsyncMock) as mock_banner:
            mock_banner.return_value = "SSH-2.0-OpenSSH_8.9p1"
            results = await detect_services("10.0.0.1", [port], timeout=1.0)

        assert len(results) == 1
        assert results[0].service == "OpenSSH"

    async def test_no_banners_uses_port_lookup(self) -> None:
        port = PortResult(port=443, state="open")
        results = await detect_services(
            "10.0.0.1", [port], timeout=1.0, grab_banners=False
        )
        assert results[0].service == "HTTPS"

    async def test_empty_port_list(self) -> None:
        results = await detect_services("10.0.0.1", [], timeout=1.0)
        assert results == []
