netscan

Simple async network scanner written in Python 3.11+.




## Ethical use

Only scan networks you own or have permission to test.
Unauthorized scanning may be illegal.

Features
Async TCP connect scan (no root required)
Basic host discovery (no ICMP)
Banner grabbing (HTTP, SSH, FTP, SMTP, etc.)
Simple OS guessing (heuristics, not reliable)
CLI output with rich
Export to JSON / CSV / XML
Supports IPs, CIDR ranges, and hostnames
Rate limiting and concurrency control
Installation
git clone https://github.com/yourusername/netscan.git
cd netscan
pip install -e .

Dev install:

pip install -e ".[dev]"

Requirements: Python 3.11+

Usage

Basic:

netscan 192.168.1.1
netscan 192.168.1.0/24
netscan scanme.nmap.org

Ports:

netscan 10.0.0.1 -p 22,80,443
netscan 10.0.0.1 -p 1-1024
netscan 10.0.0.1 -p top100

Ranges:

netscan 192.168.1.1-50
netscan 10.0.0.1-10.0.0.100

Export:

netscan 192.168.1.0/24 --export json -o results.json
netscan 10.0.0.1 --export csv
netscan target.example.com --export xml
Common flags
-p / --ports – ports to scan
-t / --timeout – connection timeout
-c / --concurrency – max parallel connections
--rate – limit connections per second
--no-discovery – skip host check
--no-banners – skip service detection
--no-os – skip OS guessing
-q – quiet output
-v – verbose

Run netscan --help for full options.

Project structure
src/netscan/
├── cli.py
├── scanner.py
├── discovery.py
├── ports.py
├── services.py
├── fingerprint.py
├── exporters.py
└── utils.py
Tests
pytest
pytest --cov=netscan
Notes

This is a small project for learning and experimentation.
For serious use, use nmap.
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
