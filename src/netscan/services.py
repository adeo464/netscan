"""Service detection: banner grabbing and service/version identification."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl

from netscan.constants import BANNER_SIGNATURES, COMMON_SERVICES, SERVICE_PROBES
from netscan.ports import PortResult

logger = logging.getLogger(__name__)

# Ports to attempt TLS wrapping on (in addition to plain TCP)
_TLS_PORTS: frozenset[int] = frozenset({443, 4443, 8443, 993, 995, 465, 990, 5986})


async def grab_banner(
    ip: str,
    port: int,
    timeout: float = 3.0,
) -> str | None:
    """Grab a service banner from an open TCP port.

    Tries plain TCP first; for known TLS ports also tries an SSL handshake.

    Args:
        ip: Target IPv4 address.
        port: Open TCP port.
        timeout: Read/write timeout in seconds.

    Returns:
        Raw banner text, or None if no banner could be retrieved.
    """
    probe = SERVICE_PROBES.get(port, b"")

    banner = await _grab_tcp_banner(ip, port, probe, timeout)
    if banner:
        return banner

    # TLS portih poskusimo se z SSL wrapperjem
    if port in _TLS_PORTS:
        banner = await _grab_tls_banner(ip, port, probe, timeout)

    return banner


async def _grab_tcp_banner(
    ip: str,
    port: int,
    probe: bytes,
    timeout: float,
) -> str | None:
    """Grab banner over a plain TCP connection."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        try:
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=timeout)

            # Nekateri servisi pošljejo banner takoj ob konekciji (SSH, FTP, SMTP)
            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            if data:
                return data.decode("utf-8", errors="replace").strip()
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
    except (TimeoutError, ConnectionRefusedError, OSError):
        pass

    return None


async def _grab_tls_banner(
    ip: str,
    port: int,
    probe: bytes,
    timeout: float,
) -> str | None:
    """Grab banner over a TLS-wrapped connection."""
    ctx = ssl.create_default_context()
    # Ne preverjamo certifikata — scanner ne more vedeti kateri CA je bil uporabljen
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx),
            timeout=timeout,
        )
        try:
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=timeout)

            data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
            if data:
                return data.decode("utf-8", errors="replace").strip()
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
    except (TimeoutError, ConnectionRefusedError, OSError, ssl.SSLError):
        pass

    return None


def detect_service(
    port: int,
    banner: str | None = None,
) -> tuple[str, str]:
    """Identify service name and version from port number and banner text.

    Args:
        port: TCP port number.
        banner: Optional raw banner string.

    Returns:
        Tuple of (service_name, version_string).  Version is empty if unknown.
    """
    service_name = COMMON_SERVICES.get(port, "unknown")
    version = ""

    if not banner:
        return service_name, version

    for sig in BANNER_SIGNATURES:
        match = sig.pattern.search(banner)
        if not match:
            continue

        service_name = sig.service_name

        if sig.version_group > 0:
            try:
                grp = match.group(sig.version_group)
                version = grp.strip() if grp else ""
            except IndexError:
                version = ""
        break

    return service_name, version


async def detect_services(
    ip: str,
    open_ports: list[PortResult],
    timeout: float = 3.0,
    grab_banners: bool = True,
) -> list[PortResult]:
    """Enrich open-port results with service names, versions, and banners.

    Args:
        ip: Target IPv4 address.
        open_ports: List of open PortResult objects to enrich.
        timeout: Banner-read timeout per port.
        grab_banners: If False, only fill service name from port number.

    Returns:
        The same list with service/version/banner fields populated.
    """
    if not grab_banners:
        for result in open_ports:
            result.service, result.version = detect_service(result.port)
        return open_ports

    enriched = await asyncio.gather(
        *[_enrich_port(ip, result, timeout) for result in open_ports],
        return_exceptions=True,
    )

    out: list[PortResult] = []
    for item in enriched:
        if isinstance(item, PortResult):
            out.append(item)
        else:
            # Napaka pri banner grabbingu — vrnemo originalni result brez bannerja
            logger.debug("Service detection error: %s", item)

    return out if out else open_ports


async def _enrich_port(ip: str, result: PortResult, timeout: float) -> PortResult:
    """Add banner + service info to a single PortResult in place."""
    banner = await grab_banner(ip, result.port, timeout)
    result.banner = banner or ""
    result.service, result.version = detect_service(result.port, banner)
    return result
