"""OS fingerprinting: banner analysis, TTL probing, port-pattern heuristics."""

from __future__ import annotations

import asyncio
import logging
import re
import sys
from dataclasses import dataclass

from netscan.constants import OS_BANNER_PATTERNS, TTL_RANGES

logger = logging.getLogger(__name__)


@dataclass
class OSGuess:
    """Best-effort OS fingerprint for a host."""

    name: str
    confidence: str  # "high" | "medium" | "low"
    method: str      # "banner" | "ttl" | "port-pattern"
    details: str = ""


async def fingerprint_os(
    ip: str,
    open_ports: list[int],
    banners: dict[int, str],
) -> OSGuess | None:
    """Attempt OS fingerprinting using multiple independent methods.

    Methods tried in confidence order:
    1. Banner text analysis (highest confidence — explicit OS mentions)
    2. TTL from system ping (medium — TTL is per-hop, may differ through NAT)
    3. Port-pattern heuristics (low — only characteristic combos)

    Args:
        ip: Target IPv4 address.
        open_ports: List of open port numbers.
        banners: Map of port → banner text for ports that returned one.

    Returns:
        OSGuess, or None if no guess could be made.
    """
    guess = _fingerprint_by_banner(banners)
    if guess:
        return guess

    guess = await _fingerprint_by_ttl(ip)
    if guess:
        return guess

    return _fingerprint_by_ports(open_ports)


def _fingerprint_by_banner(banners: dict[int, str]) -> OSGuess | None:
    """Scan all collected banner text for OS-identifying strings."""
    combined = " ".join(banners.values())

    for pattern, os_name in OS_BANNER_PATTERNS:
        if pattern.search(combined):
            return OSGuess(
                name=os_name,
                confidence="high",
                method="banner",
                details="Identified from service banner",
            )

    return None


async def _fingerprint_by_ttl(ip: str) -> OSGuess | None:
    """Estimate OS from ping TTL value."""
    try:
        ttl = await _get_ttl_via_ping(ip)
    except Exception as exc:
        logger.debug("TTL probe failed for %s: %s", ip, exc)
        return None

    if ttl is None:
        return None

    for ttl_min, ttl_max, os_name in TTL_RANGES:
        if ttl_min <= ttl <= ttl_max:
            return OSGuess(
                name=os_name,
                confidence="medium",
                method="ttl",
                details=f"TTL={ttl}",
            )

    return None


async def _get_ttl_via_ping(ip: str) -> int | None:
    """Run a single system ping and parse the TTL from its output."""
    if sys.platform == "win32":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
        pattern = re.compile(r"TTL=(\d+)", re.IGNORECASE)
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        pattern = re.compile(r"ttl=(\d+)", re.IGNORECASE)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        # Ping ne sme blokirati skeniranja — omejimo čakanje
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=4.0)
        output = stdout.decode("utf-8", errors="replace")
        match = pattern.search(output)
        return int(match.group(1)) if match else None

    except (TimeoutError, FileNotFoundError, OSError):
        return None


def _fingerprint_by_ports(open_ports: list[int]) -> OSGuess | None:
    """Use characteristic port combinations to guess the OS."""
    ports = set(open_ports)

    # Windows-specific ports: MSRPC, NetBIOS-SSN, SMB
    windows_indicators = {135, 139, 445}
    if windows_indicators & ports:
        found = windows_indicators & ports
        return OSGuess(
            name="Windows",
            confidence="medium",
            method="port-pattern",
            details=f"Windows ports open: {sorted(found)}",
        )

    # Network gear: BGP or SNMP (SNMP is UDP but 161/162 sometimes TCP too)
    if {179, 161} & ports:
        return OSGuess(
            name="Network Device",
            confidence="low",
            method="port-pattern",
            details="BGP/SNMP ports present",
        )

    # Linux/Unix heuristic: SSH without Windows indicators
    if 22 in ports and not (windows_indicators & ports):
        return OSGuess(
            name="Linux/Unix",
            confidence="low",
            method="port-pattern",
            details="SSH open, no Windows-specific ports",
        )

    return None
