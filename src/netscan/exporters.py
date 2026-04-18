"""Export scan results to JSON, CSV, and XML formats."""

from __future__ import annotations

import csv
import json
import logging
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from netscan.scanner import ScanResult

logger = logging.getLogger(__name__)


def export_json(results: list[ScanResult], filepath: str) -> None:
    """Write scan results to a JSON file.

    Args:
        results: List of ScanResult objects.
        filepath: Destination file path (created or overwritten).
    """
    payload: dict[str, Any] = {
        "scan_time": datetime.now(UTC).isoformat(),
        "total_hosts": len(results),
        "hosts_up": sum(1 for r in results if r.is_up),
        "total_open_ports": sum(len(r.open_ports) for r in results),
        "hosts": [_result_to_dict(r) for r in results],
    }
    Path(filepath).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    logger.info("Exported JSON -> %s", filepath)


def export_csv(results: list[ScanResult], filepath: str) -> None:
    """Write scan results to a CSV file (one row per open port).

    Args:
        results: List of ScanResult objects.
        filepath: Destination file path (created or overwritten).
    """
    rows: list[dict[str, Any]] = []

    for r in results:
        os_name = r.os_guess.name if r.os_guess else ""
        if r.open_ports:
            for p in r.open_ports:
                rows.append({
                    "ip": r.ip,
                    "hostname": r.hostname or "",
                    "port": p.port,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "banner": (p.banner[:120] if p.banner else ""),
                    "os_guess": os_name,
                })
        else:
            rows.append({
                "ip": r.ip,
                "hostname": r.hostname or "",
                "port": "",
                "state": "no open ports" if r.is_up else "down",
                "service": "",
                "version": "",
                "banner": "",
                "os_guess": os_name,
            })

    with Path(filepath).open("w", newline="", encoding="utf-8") as fh:
        if rows:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    logger.info("Exported CSV -> %s", filepath)


def export_xml(results: list[ScanResult], filepath: str) -> None:
    """Write scan results to an XML file (nmap-compatible structure).

    Args:
        results: List of ScanResult objects.
        filepath: Destination file path (created or overwritten).
    """
    root = ET.Element("nmaprun")
    root.set("scanner", "netscan")
    root.set("start", str(int(datetime.now(UTC).timestamp())))
    root.set("version", "1.0.0")

    for r in results:
        host_elem = ET.SubElement(root, "host")

        status = ET.SubElement(host_elem, "status")
        status.set("state", "up" if r.is_up else "down")

        addr = ET.SubElement(host_elem, "address")
        addr.set("addr", r.ip)
        addr.set("addrtype", "ipv4")

        if r.hostname:
            hostnames_elem = ET.SubElement(host_elem, "hostnames")
            hn = ET.SubElement(hostnames_elem, "hostname")
            hn.set("name", r.hostname)

        if r.os_guess:
            os_elem = ET.SubElement(host_elem, "os")
            osmatch = ET.SubElement(os_elem, "osmatch")
            osmatch.set("name", r.os_guess.name)
            osmatch.set("confidence", r.os_guess.confidence)
            osmatch.set("method", r.os_guess.method)
            if r.os_guess.details:
                osmatch.set("details", r.os_guess.details)

        if r.open_ports:
            ports_elem = ET.SubElement(host_elem, "ports")
            for p in r.open_ports:
                port_elem = ET.SubElement(ports_elem, "port")
                port_elem.set("protocol", "tcp")
                port_elem.set("portid", str(p.port))

                state_elem = ET.SubElement(port_elem, "state")
                state_elem.set("state", p.state)

                svc = ET.SubElement(port_elem, "service")
                svc.set("name", p.service.lower() if p.service else "unknown")
                if p.version:
                    svc.set("version", p.version)

    tree = ET.ElementTree(root)
    # ET.indent disponibel od Python 3.9
    ET.indent(tree, space="  ")
    tree.write(filepath, encoding="unicode", xml_declaration=True)
    logger.info("Exported XML -> %s", filepath)


def _result_to_dict(result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult to a JSON-serialisable dict."""
    return {
        "ip": result.ip,
        "hostname": result.hostname,
        "is_up": result.is_up,
        "scan_duration": round(result.scan_duration, 3),
        "os_guess": (
            {
                "name": result.os_guess.name,
                "confidence": result.os_guess.confidence,
                "method": result.os_guess.method,
                "details": result.os_guess.details,
            }
            if result.os_guess
            else None
        ),
        "open_ports": [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "version": p.version,
                "banner": p.banner,
            }
            for p in result.open_ports
        ],
    }
