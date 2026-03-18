"""
Basic Network Vulnerability Scanner
Scans a target host for:
  - Open ports (TCP connect scan)
  - Service banner grabbing
  - Common misconfigurations (default credentials hint, anonymous FTP, open telnet)
  - HTTP header security analysis
  - SSL/TLS certificate expiry check

Usage:
    python scanner.py <target> [--ports <port-list>] [--timeout <sec>] [--output <file>]

Examples:
    python scanner.py scanme.nmap.org
    python scanner.py 192.168.1.1 --ports 22,80,443,8080 --timeout 2
    python scanner.py example.com --output report.json

⚠  Only scan hosts you own or have explicit written permission to test.
"""

import argparse
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port: int
    state: str          # "open" | "closed" | "filtered"
    service: str = ""   # well-known service name
    banner: str = ""    # grabbed banner text


@dataclass
class Finding:
    severity: str       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    title: str
    detail: str
    port: Optional[int] = None


@dataclass
class ScanReport:
    target: str
    resolved_ip: str
    scan_start: str
    scan_end: str
    ports: List[PortResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ── Well-known service map ────────────────────────────────────────────────────

SERVICES: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Default port list (common targets)
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

# Banners that hint at unauthenticated / risky exposure
RISKY_BANNERS = {
    "anonymous": ("HIGH",    "Anonymous access may be allowed"),
    "welcome":   ("MEDIUM",  "Service exposes a welcome banner (info leak)"),
    "root":      ("HIGH",    "Banner references 'root' — check access controls"),
    "test":      ("MEDIUM",  "Banner contains 'test' — may be a dev/staging instance"),
}

# Security headers that should be present on HTTP(S) responses
SECURITY_HEADERS = {
    "Strict-Transport-Security": ("HIGH",   "Missing HSTS header — site is vulnerable to downgrade attacks"),
    "X-Frame-Options":           ("MEDIUM", "Missing X-Frame-Options — clickjacking may be possible"),
    "X-Content-Type-Options":    ("LOW",    "Missing X-Content-Type-Options: nosniff"),
    "Content-Security-Policy":   ("MEDIUM", "Missing Content-Security-Policy header"),
    "Referrer-Policy":           ("LOW",    "Missing Referrer-Policy header"),
}


# ── Port scanning ─────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float) -> PortResult:
    """Attempt a TCP connect to host:port. Grab banner if possible."""
    result = PortResult(
        port=port,
        state="filtered",
        service=SERVICES.get(port, "unknown"),
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            result.state = "open"
            # Try to read a banner (works for FTP, SSH, SMTP, Telnet…)
            sock.settimeout(timeout)
            try:
                banner_bytes = sock.recv(1024)
                result.banner = banner_bytes.decode("utf-8", errors="replace").strip()[:200]
            except (socket.timeout, OSError):
                pass
    except ConnectionRefusedError:
        result.state = "closed"
    except (socket.timeout, OSError):
        result.state = "filtered"
    return result


def scan_ports(host: str, ports: List[int], timeout: float, workers: int = 50) -> List[PortResult]:
    """Scan all ports concurrently."""
    results: List[PortResult] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(scan_port, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            results.append(fut.result())
    results.sort(key=lambda r: r.port)
    return results


# ── Banner analysis ───────────────────────────────────────────────────────────

def analyze_banners(port_results: List[PortResult]) -> List[Finding]:
    findings: List[Finding] = []
    for pr in port_results:
        if pr.state != "open" or not pr.banner:
            continue
        lower = pr.banner.lower()
        for keyword, (severity, detail) in RISKY_BANNERS.items():
            if keyword in lower:
                findings.append(Finding(
                    severity=severity,
                    title=f"Suspicious banner on port {pr.port}/{pr.service}",
                    detail=f"{detail}. Banner: {pr.banner[:80]}",
                    port=pr.port,
                ))
    return findings


# ── Risky port checks ─────────────────────────────────────────────────────────

def check_risky_ports(port_results: List[PortResult]) -> List[Finding]:
    findings: List[Finding] = []
    open_ports = {pr.port for pr in port_results if pr.state == "open"}

    risky = {
        23:    ("HIGH",     "Telnet (port 23) is open — unencrypted protocol, replace with SSH"),
        445:   ("HIGH",     "SMB (port 445) is open — ensure patched against EternalBlue/WannaCry"),
        3389:  ("HIGH",     "RDP (port 3389) is exposed — restrict via firewall or VPN"),
        5900:  ("HIGH",     "VNC (port 5900) is open — often lacks strong auth"),
        6379:  ("CRITICAL", "Redis (port 6379) is open — commonly exposed with no auth by default"),
        27017: ("CRITICAL", "MongoDB (port 27017) is open — commonly exposed with no auth by default"),
        3306:  ("MEDIUM",   "MySQL (port 3306) is directly reachable — restrict to localhost"),
        5432:  ("MEDIUM",   "PostgreSQL (port 5432) is directly reachable — restrict to localhost"),
        21:    ("MEDIUM",   "FTP (port 21) is open — unencrypted; consider SFTP instead"),
        25:    ("LOW",      "SMTP (port 25) is open — verify it's not an open relay"),
    }

    for port, (severity, detail) in risky.items():
        if port in open_ports:
            findings.append(Finding(
                severity=severity,
                title=f"Potentially risky port open: {port}/{SERVICES.get(port, '?')}",
                detail=detail,
                port=port,
            ))
    return findings


# ── HTTP header analysis ──────────────────────────────────────────────────────

def check_http_headers(host: str, port: int, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"

    try:
        ctx = ssl.create_default_context() if scheme == "https" else None
        req = Request(url, headers={"User-Agent": "VulnScanner/1.0"})
        resp = urlopen(req, timeout=timeout, context=ctx)
        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check for missing security headers
        for header, (severity, detail) in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append(Finding(
                    severity=severity,
                    title=f"Missing security header: {header}",
                    detail=detail,
                    port=port,
                ))

        # Check for server version disclosure
        server = headers.get("server", "")
        if server and any(char.isdigit() for char in server):
            findings.append(Finding(
                severity="LOW",
                title="Server version disclosed in header",
                detail=f"Server header reveals version info: '{server}' — consider suppressing",
                port=port,
            ))

        # HTTP only — warn about lack of encryption
        if scheme == "http":
            findings.append(Finding(
                severity="HIGH",
                title="HTTP (unencrypted) web service on port " + str(port),
                detail="Traffic is transmitted in plaintext. Enable HTTPS and redirect HTTP→HTTPS.",
                port=port,
            ))

    except (URLError, HTTPError, ssl.SSLError, OSError):
        pass  # Port not HTTP or connection failed — not a finding

    return findings


# ── SSL/TLS certificate check ─────────────────────────────────────────────────

def check_ssl_cert(host: str, port: int, timeout: float) -> List[Finding]:
    findings: List[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout),
                             server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (expiry - now).days
                if days_left < 0:
                    findings.append(Finding(
                        severity="CRITICAL",
                        title="SSL certificate has expired",
                        detail=f"Certificate expired {abs(days_left)} days ago ({not_after_str})",
                        port=port,
                    ))
                elif days_left < 14:
                    findings.append(Finding(
                        severity="HIGH",
                        title="SSL certificate expiring very soon",
                        detail=f"Certificate expires in {days_left} days ({not_after_str})",
                        port=port,
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        severity="MEDIUM",
                        title="SSL certificate expiring soon",
                        detail=f"Certificate expires in {days_left} days ({not_after_str})",
                        port=port,
                    ))
                else:
                    findings.append(Finding(
                        severity="INFO",
                        title="SSL certificate valid",
                        detail=f"Certificate valid for {days_left} more days (expires {not_after_str})",
                        port=port,
                    ))
    except (ssl.SSLError, ssl.CertificateError) as e:
        findings.append(Finding(
            severity="HIGH",
            title="SSL/TLS error on port " + str(port),
            detail=str(e),
            port=port,
        ))
    except (socket.timeout, OSError, ConnectionRefusedError):
        pass

    return findings


# ── Main scan orchestrator ────────────────────────────────────────────────────

def run_scan(target: str, ports: List[int], timeout: float) -> ScanReport:
    print(f"\n[*] Resolving {target}...")
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] Could not resolve '{target}': {e}")
        sys.exit(1)

    print(f"[*] Resolved to {resolved_ip}")
    print(f"[*] Scanning {len(ports)} ports on {target} ({resolved_ip})...")

    start = datetime.now(timezone.utc)

    report = ScanReport(
        target=target,
        resolved_ip=resolved_ip,
        scan_start=start.isoformat(),
        scan_end="",
    )

    # 1. Port scan
    report.ports = scan_ports(resolved_ip, ports, timeout)
    open_count = sum(1 for p in report.ports if p.state == "open")
    print(f"[*] Port scan complete — {open_count} open port(s) found")

    # 2. Banner analysis
    report.findings += analyze_banners(report.ports)

    # 3. Risky port checks
    report.findings += check_risky_ports(report.ports)

    # 4. HTTP header checks (on open HTTP/HTTPS ports)
    http_ports = [p.port for p in report.ports
                  if p.state == "open" and p.port in (80, 443, 8080, 8443)]
    for hp in http_ports:
        print(f"[*] Checking HTTP headers on port {hp}...")
        report.findings += check_http_headers(target, hp, timeout)

    # 5. SSL cert check on TLS ports
    tls_ports = [p.port for p in report.ports
                 if p.state == "open" and p.port in (443, 8443)]
    for tp in tls_ports:
        print(f"[*] Checking SSL certificate on port {tp}...")
        report.findings += check_ssl_cert(target, tp, timeout)

    report.scan_end = datetime.now(timezone.utc).isoformat()
    return report


# ── Output ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH":     "\033[31m",  # red
    "MEDIUM":   "\033[33m",  # yellow
    "LOW":      "\033[36m",  # cyan
    "INFO":     "\033[37m",  # white
}
RESET = "\033[0m"


def print_report(report: ScanReport) -> None:
    W = 60
    print(f"\n{'═' * W}")
    print(f"  🔍 VULNERABILITY SCAN REPORT")
    print(f"{'═' * W}")
    print(f"  Target     : {report.target}")
    print(f"  Resolved   : {report.resolved_ip}")
    print(f"  Scan start : {report.scan_start}")
    print(f"  Scan end   : {report.scan_end}")

    # Open ports table
    print(f"\n{'─' * W}")
    print(f"  OPEN PORTS ({len(report.open_ports)})")
    print(f"{'─' * W}")
    if report.open_ports:
        print(f"  {'PORT':<8} {'SERVICE':<14} {'BANNER'}")
        for pr in report.open_ports:
            banner_preview = (pr.banner[:35] + "…") if len(pr.banner) > 35 else pr.banner
            print(f"  {pr.port:<8} {pr.service:<14} {banner_preview}")
    else:
        print("  No open ports detected.")

    # Findings
    sorted_findings = sorted(report.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    print(f"\n{'─' * W}")
    print(f"  FINDINGS ({len(report.findings)})")
    print(f"{'─' * W}")

    if not sorted_findings:
        print("  No findings.")
    else:
        for f in sorted_findings:
            color = SEVERITY_COLOR.get(f.severity, "")
            port_str = f" [port {f.port}]" if f.port else ""
            print(f"\n  {color}[{f.severity}]{RESET}{port_str}  {f.title}")
            print(f"  └─ {f.detail}")

    # Summary
    summary = report.summary()
    print(f"\n{'─' * W}")
    print(f"  SUMMARY")
    print(f"{'─' * W}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = summary.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLOR.get(sev, "")
            print(f"  {color}{sev:<10}{RESET} : {count}")

    print(f"{'═' * W}\n")


def save_json(report: ScanReport, path: str) -> None:
    data = asdict(report)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Report saved to {path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_ports(port_str: str) -> List[int]:
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    parser = argparse.ArgumentParser(
        description="Basic Network Vulnerability Scanner",
        epilog="⚠ Only scan hosts you own or have explicit permission to test.",
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument(
        "--ports", "-p",
        default=",".join(map(str, DEFAULT_PORTS)),
        help="Comma-separated ports or ranges (e.g. 22,80,443 or 1-1024). Default: common ports",
    )
    parser.add_argument("--timeout", "-t", type=float, default=1.5, help="Connection timeout in seconds (default: 1.5)")
    parser.add_argument("--output", "-o", help="Save JSON report to this file path")
    args = parser.parse_args()

    print("╔══════════════════════════════════════════╗")
    print("║   Basic Vulnerability Scanner v1.0       ║")
    print("║   ⚠  Authorized use only                 ║")
    print("╚══════════════════════════════════════════╝")

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Invalid port specification: {e}")
        sys.exit(1)

    report = run_scan(args.target, ports, args.timeout)
    print_report(report)

    if args.output:
        save_json(report, args.output)


if __name__ == "__main__":
    main()
