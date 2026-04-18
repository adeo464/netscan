# Changelog

All notable changes to netscan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

## [1.0.0] - 2024-01-01

### Added
- Async TCP connect port scanner with configurable concurrency (`asyncio.Semaphore`)
- Host discovery via TCP probing (no ICMP / root required)
- Service detection: banner grabbing for SSH, HTTP, HTTPS, FTP, SMTP, Redis and more
- OS fingerprinting via banner analysis, TTL, and port-pattern heuristics
- Rich terminal output: colored tables and live progress bar
- Export to JSON, CSV, and XML (nmap-compatible structure)
- Target formats: single IP, hostname, CIDR notation, IP range (last-octet or full)
- Port formats: single, comma list, range, `top100`, `top1000`
- Rate limiting option (`--rate`)
- Verbose (`-v`) and quiet (`-q`) output modes
- GitHub Actions CI: ruff lint + pytest on Python 3.11/3.12/3.13
- Unit test suite with >70 % coverage requirement
