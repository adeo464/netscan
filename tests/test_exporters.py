"""Tests for netscan.exporters: JSON, CSV, XML output."""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from netscan.exporters import export_csv, export_json, export_xml
from netscan.fingerprint import OSGuess
from netscan.ports import PortResult
from netscan.scanner import ScanResult


def _make_result(
    ip: str = "192.168.1.1",
    is_up: bool = True,
    open_ports: list[PortResult] | None = None,
    os_guess: OSGuess | None = None,
) -> ScanResult:
    result = ScanResult(ip=ip, is_up=is_up)
    result.open_ports = open_ports or []
    result.os_guess = os_guess
    result.scan_duration = 1.23
    return result


class TestExportJson:
    def test_creates_file(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.json")
        export_json([_make_result()], out)
        assert Path(out).exists()

    def test_structure(self, tmp_path: Path) -> None:
        port = PortResult(port=80, state="open", service="HTTP", version="Apache 2.4")
        result = _make_result(open_ports=[port])
        out = str(tmp_path / "out.json")
        export_json([result], out)

        data = json.loads(Path(out).read_text())
        assert data["total_hosts"] == 1
        assert data["hosts_up"] == 1
        assert data["total_open_ports"] == 1
        assert data["hosts"][0]["ip"] == "192.168.1.1"
        assert data["hosts"][0]["open_ports"][0]["port"] == 80

    def test_empty_results(self, tmp_path: Path) -> None:
        out = str(tmp_path / "empty.json")
        export_json([], out)
        data = json.loads(Path(out).read_text())
        assert data["total_hosts"] == 0
        assert data["hosts"] == []

    def test_os_guess_included(self, tmp_path: Path) -> None:
        guess = OSGuess(name="Linux", confidence="high", method="banner")
        result = _make_result(os_guess=guess)
        out = str(tmp_path / "out.json")
        export_json([result], out)
        data = json.loads(Path(out).read_text())
        assert data["hosts"][0]["os_guess"]["name"] == "Linux"

    def test_valid_json(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.json")
        export_json([_make_result(), _make_result(ip="10.0.0.2")], out)
        # Should not raise
        json.loads(Path(out).read_text())


class TestExportCsv:
    def test_creates_file(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.csv")
        export_csv([_make_result()], out)
        assert Path(out).exists()

    def test_has_header_row(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.csv")
        export_csv([_make_result()], out)
        with Path(out).open() as fh:
            reader = csv.DictReader(fh)
            assert reader.fieldnames is not None
            assert "ip" in reader.fieldnames
            assert "port" in reader.fieldnames

    def test_one_row_per_open_port(self, tmp_path: Path) -> None:
        ports = [
            PortResult(port=22, state="open", service="SSH"),
            PortResult(port=80, state="open", service="HTTP"),
        ]
        result = _make_result(open_ports=ports)
        out = str(tmp_path / "out.csv")
        export_csv([result], out)

        with Path(out).open() as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 2
        assert {r["port"] for r in rows} == {"22", "80"}

    def test_host_down_produces_single_row(self, tmp_path: Path) -> None:
        result = _make_result(is_up=False)
        out = str(tmp_path / "out.csv")
        export_csv([result], out)
        with Path(out).open() as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == 1
        assert rows[0]["state"] == "down"


class TestExportXml:
    def test_creates_file(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.xml")
        export_xml([_make_result()], out)
        assert Path(out).exists()

    def test_valid_xml(self, tmp_path: Path) -> None:
        port = PortResult(port=443, state="open", service="HTTPS", version="nginx 1.22")
        result = _make_result(open_ports=[port])
        out = str(tmp_path / "out.xml")
        export_xml([result], out)
        # Should not raise
        ET.parse(out)

    def test_root_element_is_nmaprun(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.xml")
        export_xml([_make_result()], out)
        tree = ET.parse(out)
        assert tree.getroot().tag == "nmaprun"

    def test_host_ip_in_xml(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.xml")
        export_xml([_make_result(ip="10.1.2.3")], out)
        tree = ET.parse(out)
        addresses = tree.findall(".//address")
        assert any(a.get("addr") == "10.1.2.3" for a in addresses)

    def test_port_appears_in_xml(self, tmp_path: Path) -> None:
        port = PortResult(port=22, state="open", service="SSH")
        result = _make_result(open_ports=[port])
        out = str(tmp_path / "out.xml")
        export_xml([result], out)
        tree = ET.parse(out)
        ports = tree.findall(".//port")
        assert any(p.get("portid") == "22" for p in ports)
