"""Core scan orchestration: per-host async pipeline."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from netscan.discovery import check_host
from netscan.fingerprint import OSGuess, fingerprint_os
from netscan.ports import PortResult, scan_ports
from netscan.services import detect_services

logger = logging.getLogger(__name__)

# Callback type: called after each host completes
ProgressCallback = Callable[[str, int, int], None]


@dataclass
class ScanResult:
    """Complete result for a single scanned host."""

    ip: str
    hostname: str | None = None
    is_up: bool = False
    open_ports: list[PortResult] = field(default_factory=list)
    os_guess: OSGuess | None = None
    scan_duration: float = 0.0
    error: str | None = None


@dataclass
class ScanConfig:
    """All tunable parameters for a scan run."""

    ports: list[int]
    timeout: float = 1.0
    concurrency: int = 100
    rate_limit: float | None = None   # max new connections per second
    grab_banners: bool = True
    os_detection: bool = True
    host_discovery: bool = True
    service_timeout: float = 3.0


class Scanner:
    """Async network scanner — coordinates discovery, port scan, and enrichment."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        # En semaphore za celotno skeniranje — omeji skupno število konekcij
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def scan(
        self,
        targets: list[str],
        progress_callback: ProgressCallback | None = None,
    ) -> list[ScanResult]:
        """Scan all targets and return a list of results.

        Args:
            targets: List of IPv4 addresses to scan.
            progress_callback: Called with (ip, completed, total) after each host.

        Returns:
            List of ScanResult, one per target.
        """
        total = len(targets)
        tasks: list[asyncio.Task[ScanResult]] = []

        for idx, ip in enumerate(targets):
            task = asyncio.create_task(
                self._scan_host(ip, idx, total, progress_callback),
                name=f"scan-{ip}",
            )
            tasks.append(task)

            # Rate limiting: upočasnimo kreacijo taskov, ne čakamo med konekcijami
            if self.config.rate_limit and self.config.rate_limit > 0:
                await asyncio.sleep(1.0 / self.config.rate_limit)

        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        results: list[ScanResult] = []
        for item in gathered:
            if isinstance(item, ScanResult):
                results.append(item)
            elif isinstance(item, Exception):
                logger.error("Scan task raised: %s", item)

        return results

    async def _scan_host(
        self,
        ip: str,
        index: int,
        total: int,
        progress_callback: ProgressCallback | None,
    ) -> ScanResult:
        """Run the full scan pipeline for one host.

        Pipeline stages:
        1. Host discovery (TCP probe to common ports)
        2. Port scan (TCP connect across all specified ports)
        3. Service detection + banner grabbing (parallel per open port)
        4. OS fingerprinting (banner → TTL → port-pattern)
        """
        result = ScanResult(ip=ip)
        t0 = time.monotonic()

        try:
            # --- Stage 1: Discovery ---
            if self.config.host_discovery:
                is_up = await check_host(ip, self.config.timeout, self._semaphore)
                result.is_up = is_up
                if not is_up:
                    logger.debug("%s: appears down, skipping", ip)
                    result.scan_duration = time.monotonic() - t0
                    if progress_callback:
                        progress_callback(ip, index + 1, total)
                    return result
            else:
                result.is_up = True

            # --- Stage 2: Port scan ---
            all_results = await scan_ports(
                ip=ip,
                ports=self.config.ports,
                timeout=self.config.timeout,
                semaphore=self._semaphore,
            )
            open_results = [r for r in all_results if r.state == "open"]
            result.open_ports = open_results

            # --- Stage 3: Service detection ---
            if open_results:
                result.open_ports = await detect_services(
                    ip=ip,
                    open_ports=open_results,
                    timeout=self.config.service_timeout,
                    grab_banners=self.config.grab_banners,
                )

            # --- Stage 4: OS fingerprinting ---
            if self.config.os_detection and result.open_ports:
                banners = {
                    p.port: p.banner
                    for p in result.open_ports
                    if p.banner
                }
                result.os_guess = await fingerprint_os(
                    ip=ip,
                    open_ports=[p.port for p in result.open_ports],
                    banners=banners,
                )

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Unexpected error scanning %s: %s", ip, exc, exc_info=True)
            result.error = str(exc)

        result.scan_duration = time.monotonic() - t0

        if progress_callback:
            progress_callback(ip, index + 1, total)

        return result
