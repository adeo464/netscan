"""Tests for netscan.utils: target/port parsing and helper functions."""

from __future__ import annotations

import pytest

from netscan.utils import format_duration, is_valid_ip, parse_ports, parse_targets

# ---------------------------------------------------------------------------
# parse_targets
# ---------------------------------------------------------------------------

class TestParseTargets:
    def test_single_ipv4(self) -> None:
        assert parse_targets("10.0.0.1") == ["10.0.0.1"]

    def test_cidr_slash30(self) -> None:
        result = parse_targets("192.168.1.0/30")
        # /30 has two usable host addresses: .1 and .2
        assert result == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_slash32_single_host(self) -> None:
        result = parse_targets("10.0.0.5/32")
        assert result == ["10.0.0.5"]

    def test_last_octet_range(self) -> None:
        result = parse_targets("192.168.1.10-12")
        assert result == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    def test_full_ip_range(self) -> None:
        result = parse_targets("10.0.0.1-10.0.0.3")
        assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_invalid_cidr_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid CIDR"):
            parse_targets("999.999.999.999/24")

    def test_invalid_hostname_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot resolve"):
            parse_targets("this.hostname.does.not.exist.invalid")

    def test_cidr_too_large_raises(self) -> None:
        with pytest.raises(ValueError, match="max 65,536"):
            parse_targets("10.0.0.0/8")

    def test_range_start_greater_than_end_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_targets("192.168.1.50-192.168.1.10")

    def test_single_ip_is_list(self) -> None:
        result = parse_targets("127.0.0.1")
        assert isinstance(result, list)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# parse_ports
# ---------------------------------------------------------------------------

class TestParsePorts:
    def test_single_port(self) -> None:
        assert parse_ports("80") == [80]

    def test_comma_separated(self) -> None:
        assert parse_ports("80,443,8080") == [80, 443, 8080]

    def test_range(self) -> None:
        assert parse_ports("1-5") == [1, 2, 3, 4, 5]

    def test_mixed(self) -> None:
        result = parse_ports("22,80,8000-8002,443")
        assert result == [22, 80, 443, 8000, 8001, 8002]

    def test_top100_keyword(self) -> None:
        result = parse_ports("top100")
        assert isinstance(result, list)
        # "top100" is a nominal label — the list contains ~100 high-frequency ports
        assert 90 <= len(result) <= 110
        assert all(1 <= p <= 65535 for p in result)
        assert result == sorted(result)

    def test_top1000_keyword(self) -> None:
        result = parse_ports("top1000")
        assert len(result) > 100
        assert result == sorted(set(result))

    def test_port_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_ports("99999")

    def test_port_zero_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_ports("0")

    def test_range_start_gt_end_raises(self) -> None:
        with pytest.raises(ValueError, match="start > end"):
            parse_ports("100-50")

    def test_invalid_string_raises(self) -> None:
        with pytest.raises(ValueError):
            parse_ports("http")

    def test_deduplication(self) -> None:
        # Duplicate ports should be deduplicated
        result = parse_ports("80,80,443")
        assert result.count(80) == 1

    def test_result_is_sorted(self) -> None:
        result = parse_ports("443,80,22")
        assert result == sorted(result)


# ---------------------------------------------------------------------------
# is_valid_ip
# ---------------------------------------------------------------------------

class TestIsValidIp:
    def test_valid_ips(self) -> None:
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("0.0.0.0") is True
        assert is_valid_ip("255.255.255.255") is True

    def test_invalid_ips(self) -> None:
        assert is_valid_ip("256.0.0.1") is False
        assert is_valid_ip("not-an-ip") is False
        assert is_valid_ip("") is False
        assert is_valid_ip("192.168.1") is False


# ---------------------------------------------------------------------------
# format_duration
# ---------------------------------------------------------------------------

class TestFormatDuration:
    def test_milliseconds(self) -> None:
        assert format_duration(0.5) == "500ms"

    def test_seconds(self) -> None:
        result = format_duration(2.5)
        assert result == "2.5s"

    def test_minutes(self) -> None:
        result = format_duration(90.0)
        assert "m" in result and "s" in result
