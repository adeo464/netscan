"""TCP port scanning: connect-based scan with async concurrency."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PortResult:
    """Result of scanning a single TCP port."""

    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""
    banner: str = ""
    version: str = ""


async def scan_port(
    ip: str,
    port: int,
    timeout: float,
    semaphore: asyncio.Semaphore,
) -> PortResult:
    """Attempt a TCP connect to one port and return its state.

    Args:
        ip: Target IPv4 address.
        port: TCP port number.
        timeout: Connect timeout in seconds.
        semaphore: Shared semaphore to cap total concurrent connections.

    Returns:
        PortResult with state "open", "closed", or "filtered".
    """
    async with semaphore:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            # Port is reachable — close cleanly
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            logger.debug("Port %d on %s: open", port, ip)
            return PortResult(port=port, state="open")

        except TimeoutError:
            # No response within timeout — likely firewalled
            return PortResult(port=port, state="filtered")

        except ConnectionRefusedError:
            # RST received — port is actively closed
            return PortResult(port=port, state="closed")

        except OSError as exc:
            # Network unreachable, host down, etc.
            logger.debug("Port %d on %s: %s", port, ip, exc)
            return PortResult(port=port, state="filtered")


async def scan_ports(
    ip: str,
    ports: list[int],
    timeout: float,
    semaphore: asyncio.Semaphore,
    progress_callback: Callable[[PortResult], None] | None = None,
) -> list[PortResult]:
    """Scan all specified ports on a single host concurrently.

    Args:
        ip: Target IPv4 address.
        ports: List of TCP port numbers to scan.
        timeout: Per-port connect timeout in seconds.
        semaphore: Shared semaphore across all concurrent scans.
        progress_callback: Optional callable invoked after each port result.

    Returns:
        List of PortResult objects sorted by port number.
    """
    tasks = [
        asyncio.create_task(scan_port(ip, port, timeout, semaphore))
        for port in ports
    ]

    results: list[PortResult] = []
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        if progress_callback is not None:
            progress_callback(result)

    return sorted(results, key=lambda r: r.port)
