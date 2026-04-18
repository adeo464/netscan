"""netscan — Modern async network scanner."""

from netscan.fingerprint import OSGuess
from netscan.ports import PortResult
from netscan.scanner import ScanConfig, Scanner, ScanResult

__version__ = "1.0.0"
__author__ = "netscan contributors"

__all__ = [
    "Scanner",
    "ScanConfig",
    "ScanResult",
    "PortResult",
    "OSGuess",
    "__version__",
]
