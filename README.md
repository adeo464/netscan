# netscan

> Modern async network scanner written in Python 3.11+

<!-- TODO: add demo.gif -->

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/yourusername/netscan/actions/workflows/ci.yml/badge.svg)

---

## ⚠️ Ethical Use

**Only scan networks you own or have explicit written permission to test.**
Unauthorized port scanning may be illegal in your jurisdiction.
netscan is intended for authorized security assessments, CTF challenges, and learning.

---

## ✨ Features

- 🚀 **Async TCP connect scan** — asyncio-powered, no root or PCAP required
- 🔍 **Host discovery** — TCP probing to common ports (no ICMP)
- 🏷️ **Service detection** — banner grabbing for SSH, HTTP/S, FTP, SMTP, MySQL, Redis, RDP and more
- 🖥️ **OS fingerprinting** — banner analysis → TTL heuristic → port-pattern fallback
- 📊 **Rich output** — colored tables and live progress bar (via `rich`)
- 📁 **Export** — JSON, CSV, XML (nmap-compatible structure)
- 🎯 **Flexible targets** — single IP, hostname, CIDR (`192.168.1.0/24`), range (`192.168.1.1-50`)
- 🔢 **Flexible ports** — comma list, range, `top100`, `top1000`
- ⏱️ **Rate limiting** — `--rate` flag to avoid flooding
- 🛑 **Graceful Ctrl+C** — cancels all pending work cleanly

---

## 📦 Installation

```bash
git clone https://github.com/yourusername/netscan.git
cd netscan
pip install -e .
```

To install with development dependencies:

```bash
pip install -e ".[dev]"
```

**Requirements:** Python 3.11+, pip

---

## 🚀 Usage

### Basic scan

```bash
# Scan a single host (top 100 ports)
netscan 192.168.1.1

# Scan a subnet
netscan 192.168.1.0/24

# Scan a hostname
netscan scanme.nmap.org
```

### Port specification

```bash
# Specific ports
netscan 10.0.0.1 -p 22,80,443

# Port range
netscan 10.0.0.1 -p 1-1024

# Top 100 common ports (default)
netscan 10.0.0.1 -p top100

# Top 1000 common ports
netscan 10.0.0.1 -p top1000
```

### IP ranges

```bash
# Last-octet range
netscan 192.168.1.1-50

# Full range
netscan 10.0.0.1-10.0.0.100
```

### Export results

```bash
# Export to JSON
netscan 192.168.1.0/24 -p top100 --export json -o scan_results.json

# Export to CSV
netscan 10.0.0.1 -p 1-65535 --export csv

# Export to XML (nmap-compatible)
netscan target.example.com --export xml -o report.xml
```

### Advanced options

```bash
# Custom timeout and concurrency
netscan 10.0.0.1 -p top1000 --timeout 2.0 --concurrency 200

# Rate limit (max 50 connections/second)
netscan 192.168.1.0/24 --rate 50

# Skip host discovery (scan all targets regardless)
netscan 10.0.0.1 -p 22,80,443 --no-discovery

# Skip banner grabbing (faster)
netscan 192.168.1.0/24 --no-banners

# Skip OS detection
netscan 10.0.0.1 --no-os

# Quiet mode (results table only)
netscan 10.0.0.1 -q

# Verbose / debug logging
netscan 10.0.0.1 -v
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | — | IP, hostname, CIDR, or range |
| `-p / --ports` | `top100` | Port specification |
| `-t / --timeout` | `1.0` | Connection timeout (seconds) |
| `-c / --concurrency` | `100` | Max simultaneous connections |
| `--no-discovery` | off | Skip host discovery |
| `--no-banners` | off | Skip banner grabbing |
| `--no-os` | off | Skip OS fingerprinting |
| `--rate` | none | Rate limit (connections/sec) |
| `--export` | none | `json` \| `csv` \| `xml` |
| `-o / --output` | auto | Output file path |
| `-v / --verbose` | off | Debug logging |
| `-q / --quiet` | off | Results only |

---

## 🏗️ Architecture

```
src/netscan/
├── cli.py          # Typer CLI — argument parsing, rich display
├── scanner.py      # Orchestration — hosts × ports pipeline
├── discovery.py    # Host discovery (TCP probe)
├── ports.py        # TCP connect scan, PortResult dataclass
├── services.py     # Banner grabbing, service/version detection
├── fingerprint.py  # OS fingerprinting (banner, TTL, ports)
├── exporters.py    # JSON / CSV / XML writers
├── constants.py    # Port lists, service names, banner patterns
└── utils.py        # Target/port parsing, helpers
```

### Scan pipeline per host

```
parse_targets() → [IPs]
    └─► check_host()          (TCP probe to common ports)
            └─► scan_ports()  (async TCP connect, semaphore-limited)
                    └─► detect_services()  (banner grab + pattern match)
                            └─► fingerprint_os()  (banner → TTL → ports)
```

---

## 🧪 Running Tests

```bash
# Run all tests
pytest

# With coverage report
pytest --cov=netscan --cov-report=term-missing

# Fast (no coverage)
pytest -x
```

---

## ⚙️ Development

```bash
# Format code
ruff format src/ tests/

# Lint
ruff check src/ tests/

# Fix auto-fixable issues
ruff check --fix src/ tests/
```

---

## 📊 netscan vs nmap

| Feature | netscan | nmap |
|---------|---------|------|
| TCP connect scan | ✅ | ✅ |
| SYN stealth scan | ❌ (root) | ✅ (root) |
| UDP scan | ❌ | ✅ |
| OS detection | Basic (heuristics) | Advanced |
| Scripting engine | ❌ | ✅ (NSE) |
| No root required | ✅ | Partial |
| Install size | ~5 MB | ~30 MB |
| Python API | ✅ | ❌ |

**netscan is a learning project, not a replacement for nmap.**
For professional security assessments, use nmap.

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Write tests for your change
4. Ensure `ruff check` and `pytest` pass
5. Submit a pull request

Please follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

---

## 📄 License

MIT — see [LICENSE](LICENSE).
