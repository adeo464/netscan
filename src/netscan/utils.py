"""Utility functions: target/port parsing, IP validation, formatting."""

from __future__ import annotations

import ipaddress
import logging
import socket

from netscan.constants import TOP_100_PORTS, TOP_1000_PORTS

logger = logging.getLogger(__name__)


def parse_targets(target: str) -> list[str]:
    """Parse target specification into a list of IPv4 address strings.

    Args:
        target: One of:
            - Single IP: ``192.168.1.1``
            - Hostname: ``example.com``
            - CIDR: ``192.168.1.0/24``
            - Last-octet range: ``192.168.1.1-50``
            - Full-range: ``192.168.1.1-192.168.1.50``

    Returns:
        Sorted list of IPv4 address strings.

    Raises:
        ValueError: If the target is malformed or unresolvable.
    """
    target = target.strip()

    if "/" in target:
        return _expand_cidr(target)

    if "-" in target:
        parts = target.rsplit("-", 1)
        last = parts[1]
        if "." in last:
            # Full IP range: 192.168.1.1-192.168.1.50
            return _expand_ip_range(parts[0], last)
        # Last-octet range: 192.168.1.1-50
        octets = parts[0].split(".")
        if len(octets) != 4:
            raise ValueError(f"Invalid IP range format: {target!r}")
        base = ".".join(octets[:3])
        try:
            start = int(octets[3])
            end = int(last)
        except ValueError as exc:
            raise ValueError(f"Invalid IP range format: {target!r}") from exc
        if not (0 <= start <= 255 and 0 <= end <= 255 and start <= end):
            raise ValueError(f"Invalid octet range {start}-{end}")
        return [f"{base}.{i}" for i in range(start, end + 1)]

    # Single IP or hostname — resolve to get canonical IP string
    try:
        resolved = socket.gethostbyname(target)
        return [resolved]
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {target!r}: {exc}") from exc


def _expand_cidr(cidr: str) -> list[str]:
    """Expand CIDR notation to a list of host addresses."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR {cidr!r}: {exc}") from exc

    if network.num_addresses > 65_536:
        raise ValueError(
            f"Network {cidr} has {network.num_addresses:,} addresses (max 65,536). "
            "Use a smaller subnet or scan ranges."
        )

    # /32 single host — .hosts() returns empty generator, so handle separately
    if network.prefixlen == 32:
        return [str(network.network_address)]
    return [str(ip) for ip in network.hosts()]


def _expand_ip_range(start_ip: str, end_ip: str) -> list[str]:
    """Expand a start–end IP range to a list of addresses."""
    try:
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
    except ValueError as exc:
        raise ValueError(f"Invalid IP in range: {exc}") from exc

    if start > end:
        raise ValueError(f"Start IP {start_ip} must be <= end IP {end_ip}")

    count = int(end) - int(start) + 1
    if count > 65_536:
        raise ValueError(f"Range too large ({count:,} addresses, max 65,536)")

    return [str(ipaddress.IPv4Address(int(start) + i)) for i in range(count)]


def parse_ports(port_spec: str) -> list[int]:
    """Parse a port specification into a sorted list of integers.

    Args:
        port_spec: One of:
            - Keyword: ``top100``, ``top1000``
            - Single port: ``80``
            - Comma list: ``80,443,8080``
            - Range: ``1-1024``
            - Mixed: ``22,80,443,8000-8100``

    Returns:
        Sorted list of port numbers.

    Raises:
        ValueError: If any port or range is invalid.
    """
    spec = port_spec.strip().lower()

    if spec == "top100":
        return sorted(TOP_100_PORTS)
    if spec == "top1000":
        return sorted(TOP_1000_PORTS)

    ports: set[int] = set()

    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue

        if "-" in part:
            pieces = part.split("-", 1)
            try:
                lo, hi = int(pieces[0]), int(pieces[1])
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {part!r}") from exc
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"Ports must be 1-65535, got: {part!r}")
            if lo > hi:
                raise ValueError(f"Range start > end: {part!r}")
            ports.update(range(lo, hi + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ValueError(f"Not a valid port number: {part!r}") from exc
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of range (1–65535)")
            ports.add(port)

    if not ports:
        raise ValueError(f"No valid ports parsed from: {port_spec!r}")

    return sorted(ports)


def is_valid_ip(ip: str) -> bool:
    """Return True if the string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string."""
    if seconds < 1.0:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.0f}s"
