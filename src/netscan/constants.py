"""Constants: top ports, service names, banner signatures, OS fingerprint patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Most common 100 ports (derived from nmap frequency data)
TOP_100_PORTS: list[int] = sorted([
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
    8888, 9100, 9999, 10000, 32768, 49152, 49153,
])

# Extended top-1000 list
TOP_1000_PORTS: list[int] = sorted(set(list(range(1, 1025)) + TOP_100_PORTS + [
    1080, 1194, 1433, 1521, 1723, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2375, 2376, 3268, 3269, 3306, 3389, 4443, 4848, 5000, 5432,
    5672, 5900, 5985, 5986, 6379, 6443, 7001, 7002, 7443, 7474, 8080,
    8140, 8161, 8443, 8880, 8888, 9000, 9090, 9093, 9200, 9300, 9418,
    10250, 11211, 15672, 16443, 27017, 27018, 27019, 28017, 50000, 61616,
]))

# Port → human-readable service name
COMMON_SERVICES: dict[int, str] = {
    7: "Echo", 9: "Discard", 13: "Daytime", 21: "FTP", 22: "SSH",
    23: "Telnet", 25: "SMTP", 53: "DNS", 79: "Finger", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "RPC", 113: "Ident",
    119: "NNTP", 135: "MS-RPC", 139: "NetBIOS-SSN", 143: "IMAP",
    179: "BGP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Shell/Syslog", 515: "Printer",
    587: "SMTP-Sub", 631: "IPP", 873: "Rsync", 990: "FTPS",
    993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Dev-HTTP", 3268: "LDAP-GC", 3306: "MySQL",
    3389: "RDP", 4443: "Alt-HTTPS", 5000: "UPnP/Dev",
    5432: "PostgreSQL", 5672: "AMQP", 5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    6443: "Kubernetes-API", 7001: "WebLogic", 7474: "Neo4j",
    8000: "Alt-HTTP", 8008: "Alt-HTTP", 8080: "Alt-HTTP",
    8081: "Alt-HTTP", 8140: "Puppet", 8161: "ActiveMQ",
    8443: "Alt-HTTPS", 8888: "Alt-HTTP", 9090: "Prometheus",
    9093: "Alertmanager", 9200: "Elasticsearch",
    9300: "ES-Transport", 9418: "Git", 10250: "Kubelet",
    11211: "Memcached", 15672: "RabbitMQ-Mgmt",
    27017: "MongoDB", 27018: "MongoDB", 61616: "ActiveMQ-JMS",
}

# Bytes to send immediately after connection to elicit a banner
SERVICE_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    4443: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    8008: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    8081: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    3000: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    9090: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    9200: b"HEAD / HTTP/1.0\r\nHost: netscan\r\n\r\n",
    6379: b"PING\r\n",
    # Services that push a banner on connect need no probe
    21: b"",
    22: b"",
    23: b"",
    25: b"",
    110: b"",
    143: b"",
    993: b"",
    995: b"",
}

# Ports tried during host discovery (common, high response-rate ports)
DISCOVERY_PORTS: list[int] = [80, 443, 22, 445, 3389, 8080, 25, 21]


@dataclass(frozen=True)
class BannerSignature:
    """Pattern for identifying a service and version from its banner text."""

    pattern: re.Pattern[str]
    service_name: str
    # Which capture group holds the version string; 0 means no version available
    version_group: int = 1


# Evaluated in order — first match wins
BANNER_SIGNATURES: list[BannerSignature] = [
    # SSH
    BannerSignature(
        re.compile(r"SSH-\d+\.\d+-OpenSSH_([\d.p]+\w*)", re.IGNORECASE),
        "OpenSSH",
    ),
    BannerSignature(
        re.compile(r"SSH-\d+\.\d+-Dropbear_([\d.]+)", re.IGNORECASE),
        "Dropbear SSH",
    ),
    BannerSignature(
        re.compile(r"SSH-\d+\.\d+-([\w._-]+)", re.IGNORECASE),
        "SSH",
    ),
    # HTTP server headers
    BannerSignature(
        re.compile(r"Server: Apache/([\d.]+)", re.IGNORECASE),
        "Apache httpd",
    ),
    BannerSignature(
        re.compile(r"Server: nginx/([\d.]+)", re.IGNORECASE),
        "nginx",
    ),
    BannerSignature(
        re.compile(r"Server: Microsoft-IIS/([\d.]+)", re.IGNORECASE),
        "Microsoft IIS",
    ),
    BannerSignature(
        re.compile(r"Server: lighttpd/([\d.]+)", re.IGNORECASE),
        "lighttpd",
    ),
    BannerSignature(
        re.compile(r"Server: Apache Tomcat/([\d.]+)", re.IGNORECASE),
        "Apache Tomcat",
    ),
    BannerSignature(
        re.compile(r"Server: Jetty\(?([\d.]+)?", re.IGNORECASE),
        "Jetty",
    ),
    BannerSignature(
        re.compile(r"Server: ([\w/.\-]+)", re.IGNORECASE),
        "HTTP Server",
    ),
    # FTP
    BannerSignature(
        re.compile(r"220[- ].*vsftpd\s+([\d.]+)", re.IGNORECASE),
        "vsftpd",
    ),
    BannerSignature(
        re.compile(r"220[- ].*ProFTPD\s+([\d.]+)", re.IGNORECASE),
        "ProFTPD",
    ),
    BannerSignature(
        re.compile(r"220[- ].*FileZilla Server", re.IGNORECASE),
        "FileZilla FTP",
        0,
    ),
    BannerSignature(
        re.compile(r"220[- ].*Pure-FTPd", re.IGNORECASE),
        "Pure-FTPd",
        0,
    ),
    # SMTP
    BannerSignature(
        re.compile(r"220[- ].*Postfix", re.IGNORECASE),
        "Postfix SMTP",
        0,
    ),
    BannerSignature(
        re.compile(r"220[- ].*Exim\s+([\d.]+)", re.IGNORECASE),
        "Exim",
    ),
    BannerSignature(
        re.compile(r"220[- ].*Microsoft.*ESMTP", re.IGNORECASE),
        "MS Exchange SMTP",
        0,
    ),
    BannerSignature(
        re.compile(r"220[- ].*Sendmail/([\d.]+)", re.IGNORECASE),
        "Sendmail",
    ),
    # In-memory stores
    BannerSignature(
        re.compile(r"\+PONG", re.IGNORECASE),
        "Redis",
        0,
    ),
    # Telnet / generic
    BannerSignature(
        re.compile(r"([\w-]+)/([\d]+\.[\d]+)", re.IGNORECASE),
        "Service",
        2,
    ),
]

# TTL thresholds for OS guessing (initial TTL decrements each hop)
TTL_RANGES: list[tuple[int, int, str]] = [
    (1, 64, "Linux/Unix"),
    (65, 128, "Windows"),
    (129, 255, "Network Device (Cisco/Juniper/etc)"),
]

# Substrings/patterns found in banners that reveal the OS
OS_BANNER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Ubuntu|Debian|CentOS|Red Hat|RHEL|Fedora|Kali|Arch|Gentoo", re.IGNORECASE), "Linux"),
    (re.compile(r"Microsoft Windows|Windows Server|Win32|winnt|Microsoft-IIS", re.IGNORECASE), "Windows"),
    (re.compile(r"FreeBSD|OpenBSD|NetBSD|DragonFly", re.IGNORECASE), "BSD"),
    (re.compile(r"Cisco IOS|IOS-XE|NX-OS", re.IGNORECASE), "Cisco IOS"),
    (re.compile(r"Juniper|JunOS", re.IGNORECASE), "Juniper"),
    (re.compile(r"Darwin|macOS|Mac OS X", re.IGNORECASE), "macOS"),
    (re.compile(r"VMware|ESXi", re.IGNORECASE), "VMware ESXi"),
]
