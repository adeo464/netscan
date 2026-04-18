"""Tests for netscan.fingerprint: OS fingerprinting heuristics."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from netscan.fingerprint import (
    OSGuess,
    _fingerprint_by_banner,
    _fingerprint_by_ports,
    _fingerprint_by_ttl,
    fingerprint_os,
)


class TestFingerprintByBanner:
    def test_detects_linux_from_ubuntu_string(self) -> None:
        banners = {22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"}
        result = _fingerprint_by_banner(banners)
        assert result is not None
        assert result.name == "Linux"
        assert result.confidence == "high"
        assert result.method == "banner"

    def test_detects_windows_from_iis_banner(self) -> None:
        banners = {80: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n"}
        result = _fingerprint_by_banner(banners)
        assert result is not None
        assert result.name == "Windows"

    def test_detects_cisco_from_banner(self) -> None:
        banners = {23: "User Access Verification\nCisco IOS Software"}
        result = _fingerprint_by_banner(banners)
        assert result is not None
        assert result.name == "Cisco IOS"

    def test_returns_none_for_unknown_banners(self) -> None:
        banners = {80: "HTTP/1.1 200 OK\r\nServer: nginx/1.22\r\n"}
        result = _fingerprint_by_banner(banners)
        assert result is None

    def test_returns_none_for_empty_banners(self) -> None:
        result = _fingerprint_by_banner({})
        assert result is None

    def test_detects_freebsd(self) -> None:
        banners = {22: "SSH-2.0-OpenSSH_9.0 FreeBSD-20220801"}
        result = _fingerprint_by_banner(banners)
        assert result is not None
        assert result.name == "BSD"


class TestFingerprintByPorts:
    def test_detects_windows_from_smb_ports(self) -> None:
        result = _fingerprint_by_ports([135, 139, 445])
        assert result is not None
        assert result.name == "Windows"
        assert result.confidence == "medium"

    def test_detects_windows_from_rdp_and_smb(self) -> None:
        result = _fingerprint_by_ports([445, 3389, 80])
        assert result is not None
        assert result.name == "Windows"

    def test_detects_linux_from_ssh_only(self) -> None:
        result = _fingerprint_by_ports([22, 80, 443])
        assert result is not None
        assert result.name == "Linux/Unix"
        assert result.confidence == "low"

    def test_detects_network_device_from_bgp(self) -> None:
        result = _fingerprint_by_ports([179, 22])
        assert result is not None
        assert result.name == "Network Device"

    def test_returns_none_for_empty_ports(self) -> None:
        result = _fingerprint_by_ports([])
        assert result is None

    def test_returns_none_for_ambiguous_ports(self) -> None:
        # Only uncommon ports, no clear indicator
        result = _fingerprint_by_ports([8080, 8443])
        assert result is None


class TestFingerprintByTtl:
    async def test_linux_ttl_64(self) -> None:
        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = 64
            result = await _fingerprint_by_ttl("10.0.0.1")

        assert result is not None
        assert "Linux" in result.name
        assert result.method == "ttl"

    async def test_windows_ttl_128(self) -> None:
        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = 128
            result = await _fingerprint_by_ttl("10.0.0.1")

        assert result is not None
        assert result.name == "Windows"

    async def test_network_device_ttl_255(self) -> None:
        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = 255
            result = await _fingerprint_by_ttl("10.0.0.1")

        assert result is not None
        assert "Network Device" in result.name

    async def test_returns_none_when_ping_fails(self) -> None:
        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = None
            result = await _fingerprint_by_ttl("10.0.0.1")

        assert result is None

    async def test_returns_none_on_exception(self) -> None:
        with patch(
            "netscan.fingerprint._get_ttl_via_ping",
            new_callable=AsyncMock,
            side_effect=RuntimeError("ping failed"),
        ):
            result = await _fingerprint_by_ttl("10.0.0.1")

        assert result is None


class TestFingerprintOs:
    async def test_uses_banner_first(self) -> None:
        banners = {22: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}
        result = await fingerprint_os("10.0.0.1", [22, 80], banners)
        assert result is not None
        assert result.name == "Linux"
        assert result.method == "banner"

    async def test_falls_back_to_ttl_when_no_banner_match(self) -> None:
        banners = {80: "HTTP/1.1 200 OK\r\nServer: nginx/1.22\r\n"}

        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = 64
            result = await fingerprint_os("10.0.0.1", [80], banners)

        assert result is not None
        assert result.method == "ttl"

    async def test_falls_back_to_port_pattern(self) -> None:
        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = None
            result = await fingerprint_os("10.0.0.1", [135, 445], {})

        assert result is not None
        assert result.method == "port-pattern"
        assert result.name == "Windows"

    async def test_returns_none_when_nothing_matches(self) -> None:
        with patch("netscan.fingerprint._get_ttl_via_ping", new_callable=AsyncMock) as mock_ttl:
            mock_ttl.return_value = None
            result = await fingerprint_os("10.0.0.1", [8080, 8443], {})

        assert result is None


class TestOSGuessDataclass:
    def test_fields(self) -> None:
        guess = OSGuess(name="Linux", confidence="high", method="banner", details="test")
        assert guess.name == "Linux"
        assert guess.confidence == "high"
        assert guess.method == "banner"
        assert guess.details == "test"

    def test_default_details(self) -> None:
        guess = OSGuess(name="Windows", confidence="medium", method="ttl")
        assert guess.details == ""
