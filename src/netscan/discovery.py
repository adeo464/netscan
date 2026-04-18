"""Host discovery via TCP connect probes (no ICMP / root required)."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from netscan.constants import DISCOVERY_PORTS

logger = logging.getLogger(__name__)


async def check_host(
    ip: str,
    timeout: float = 1.0,
    semaphore: asyncio.Semaphore | None = None,
) -> bool:
    """Determine whether a host is reachable by probing common TCP ports.

    Fires TCP connects to several well-known ports in parallel.  If any one
    succeeds the host is declared up; the rest are cancelled immediately.
    This avoids ICMP (which requires root) while still being fast.

    Args:
        ip: IPv4 address to probe.
        timeout: Per-probe connect timeout in seconds.
        semaphore: Optional shared semaphore (avoids flooding the network).

    Returns:
        True if at least one port responded.
    """
    if semaphore is None:
        # Lokalny semaphore da ne ustvarimo prevec hkratnih klicev brez konteksta
        semaphore = asyncio.Semaphore(len(DISCOVERY_PORTS))

    tasks = [
        asyncio.create_task(_tcp_probe(ip, port, timeout, semaphore))
        for port in DISCOVERY_PORTS
    ]

    try:
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                # Host responded — cancel remaining probes to save time
                for t in tasks:
                    t.cancel()
                return True
    finally:
        # Počakamo na cancellation da ne pustimo "floating" taskov
        await asyncio.gather(*tasks, return_exceptions=True)

    return False


async def _tcp_probe(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> bool:
    """Attempt a single TCP connect and return True on success."""
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            return True
        except (TimeoutError, ConnectionRefusedError, OSError):
            return False
        except asyncio.CancelledError:
            raise
