#!/usr/bin/env python3
"""
net-vuln-scanner/scanner.py
Automated Network Vulnerability Scanner
Wraps Nmap for host/service discovery and queries the NVD API for CVE matching.

Usage:
    python scanner.py --target 192.168.1.0/24 --output report.html
    python scanner.py --target 10.0.0.1 --ports 22,80,443 --output report.html
"""

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

import nmap
import requests

from nvd_client import NVDClient
from report_generator import ReportGenerator

#Logging 
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("scanner")

#Constants 
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "NONE":     "#6b7280",
}

CVSS_THRESHOLDS = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   4.0,
    "LOW":      0.1,
}


def cvss_to_severity(score: float) -> str:
    """Map a CVSS v3 base score to a human-readable severity band."""
    if score >= CVSS_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    if score >= CVSS_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= CVSS_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def validate_target(target: str) -> bool:
    """Accept a single IP, a CIDR range, or a hostname."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    # Allow hostnames / FQDNs (basic check)
    if target and all(c.isalnum() or c in "-._" for c in target):
        return True
    return False


class NetworkScanner:
    """
    Orchestrates Nmap scanning and CVE enrichment.

    Parameters
 
    target      : IP, CIDR subnet, or hostname to scan.
    ports       : Comma-separated port list or range (default: top-1000).
    scan_args   : Raw Nmap arguments (overrides defaults when supplied).
    nvd_api_key : NVD 2.0 API key for higher rate limits (optional).
    """

    DEFAULT_NMAP_ARGS = "-sV -sC --open -T4 --host-timeout 60s"

    def __init__(
        self,
        target: str,
        ports: Optional[str] = None,
        scan_args: Optional[str] = None,
        nvd_api_key: Optional[str] = None,
    ):
        if not validate_target(target):
            raise ValueError(f"Invalid target specification: {target!r}")

        self.target = target
        self.ports = ports
        self.scan_args = scan_args or self.DEFAULT_NMAP_ARGS
        self.nm = nmap.PortScanner()
        self.nvd = NVDClient(api_key=nvd_api_key)
        self.results: dict = {}
        self.scan_metadata: dict = {}

    #Scanning 

    def run(self) -> dict:
        """Execute the full scan pipeline and return enriched results."""
        logger.info("Starting scan on target: %s", self.target)
        start_time = time.time()

        raw = self._nmap_scan()
        enriched = self._enrich_with_cves(raw)

        elapsed = round(time.time() - start_time, 2)
        self.scan_metadata = {
            "target": self.target,
            "scan_args": self.scan_args,
            "ports_specified": self.ports,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "duration_seconds": elapsed,
            "hosts_up": sum(1 for h in enriched.values() if h["state"] == "up"),
            "total_hosts": len(enriched),
        }
        self.results = enriched
        logger.info(
            "Scan complete in %.2fs — %d hosts up of %d total",
            elapsed, self.scan_metadata["hosts_up"], self.scan_metadata["total_hosts"],
        )
        return enriched

    def _nmap_scan(self) -> dict:
        """Run Nmap and return a structured dict of host/port data."""
        args = self.scan_args
        kwargs = {"arguments": args}
        if self.ports:
            kwargs["ports"] = self.ports

        logger.info("Running nmap with args: %s", args)
        try:
            self.nm.scan(hosts=self.target, **kwargs)
        except nmap.PortScannerError as exc:
            logger.error("Nmap error: %s", exc)
            raise

        hosts: dict = {}
        for host in self.nm.all_hosts():
            host_info = self.nm[host]
            state = host_info.state()
            hostname = (host_info.hostname() or host)

            ports: list = []
            for proto in host_info.all_protocols():
                for port in sorted(host_info[proto].keys()):
                    pdata = host_info[proto][port]
                    if pdata["state"] != "open":
                        continue

                    # Build CPE list from nmap output
                    cpes = []
                    if "cpe" in pdata and pdata["cpe"]:
                        cpes = [c for c in pdata["cpe"].split(" ") if c]

                    ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": pdata["state"],
                        "service": pdata.get("name", "unknown"),
                        "product": pdata.get("product", ""),
                        "version": pdata.get("version", ""),
                        "extra_info": pdata.get("extrainfo", ""),
                        "cpes": cpes,
                        "script_output": pdata.get("script", {}),
                        "cves": [],           # populated later
                    })

            os_matches = []
            if "osmatch" in host_info:
                for osm in host_info["osmatch"][:3]:
                    os_matches.append({
                        "name": osm.get("name", ""),
                        "accuracy": osm.get("accuracy", ""),
                    })

            hosts[host] = {
                "ip": host,
                "hostname": hostname,
                "state": state,
                "ports": ports,
                "os_matches": os_matches,
            }

        return hosts

    #CVE Enrichment

    def _enrich_with_cves(self, hosts: dict) -> dict:
        """Query NVD for each discovered service/CPE and attach CVE data."""
        for host_ip, host_data in hosts.items():
            for port_entry in host_data.get("ports", []):
                cves = []

                # Strategy 1: CPE-based lookup (most accurate)
                for cpe in port_entry.get("cpes", []):
                    cves.extend(self.nvd.cves_by_cpe(cpe))

                # Strategy 2: Keyword fallback (product + version)
                if not cves and port_entry["product"]:
                    keyword = port_entry["product"]
                    if port_entry["version"]:
                        keyword += f" {port_entry['version']}"
                    cves.extend(self.nvd.cves_by_keyword(keyword, max_results=5))

                # Deduplicate by CVE ID
                seen: set = set()
                unique_cves = []
                for cve in cves:
                    if cve["id"] not in seen:
                        seen.add(cve["id"])
                        unique_cves.append(cve)

                port_entry["cves"] = sorted(
                    unique_cves,
                    key=lambda c: c.get("cvss_score", 0),
                    reverse=True,
                )

        return hosts

    #Helpers

    def save_json(self, path: str) -> None:
        """Persist raw results to JSON for further processing."""
        payload = {
            "metadata": self.scan_metadata,
            "hosts": self.results,
        }
        Path(path).write_text(json.dumps(payload, indent=2))
        logger.info("JSON results saved to %s", path)

    def summary(self) -> dict:
        """Return a severity summary across all hosts."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for host in self.results.values():
            for port in host.get("ports", []):
                for cve in port.get("cves", []):
                    sev = cvss_to_severity(cve.get("cvss_score", 0))
                    counts[sev] += 1
        return counts


#CLI Entry Point

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scanner.py",
        description=(
            "Automated Network Vulnerability Scanner\n"
            "Wraps Nmap + NVD API to identify CVEs on live hosts."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --target 192.168.1.0/24
  python scanner.py --target 10.0.0.5 --ports 22,80,443,8080
  python scanner.py --target 172.16.0.0/24 --output /reports/scan.html --json scan.json
  python scanner.py --target myhost.local --scan-args "-sV -T3 --open"
        """,
    )
    p.add_argument("--target", required=True,
                   help="IP address, CIDR subnet, or hostname")
    p.add_argument("--ports", default=None,
                   help="Ports to scan, e.g. '22,80,443' or '1-1024'")
    p.add_argument("--scan-args", default=None,
                   help="Raw nmap arguments (overrides defaults)")
    p.add_argument("--output", default="report.html",
                   help="Output path for the HTML report (default: report.html)")
    p.add_argument("--json", default=None, metavar="JSON_PATH",
                   help="Also save raw results as JSON")
    p.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                   help="NVD 2.0 API key (or set NVD_API_KEY env var)")
    p.add_argument("--min-severity", default="LOW",
                   choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
                   help="Only include CVEs at or above this severity in the report")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Enable debug logging")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Ethical gate — must confirm scope
    print("\n" + "=" * 60)
    print(" AUTOMATED NETWORK VULNERABILITY SCANNER")
    print("=" * 60)
    print(f" Target : {args.target}")
    print(f" Ports  : {args.ports or 'top-1000 (nmap default)'}")
    print(f" Output : {args.output}")
    print("=" * 60)
    print(
        "\n⚠  WARNING: Only scan networks and systems you OWN or have\n"
        "   EXPLICIT WRITTEN PERMISSION to test. Unauthorized scanning\n"
        "   is illegal and unethical. By continuing you confirm you\n"
        "   have proper authorization.\n"
    )
    try:
        confirm = input("Type 'YES' to proceed: ").strip().upper()
    except (EOFError, KeyboardInterrupt):
        confirm = ""

    if confirm != "YES":
        print("Scan aborted.")
        return 1

    # Run scan
    scanner = NetworkScanner(
        target=args.target,
        ports=args.ports,
        scan_args=args.scan_args,
        nvd_api_key=args.nvd_api_key,
    )

    try:
        scanner.run()
    except Exception as exc:
        logger.error("Scan failed: %s", exc)
        return 2

    # Optionally persist JSON
    if args.json:
        scanner.save_json(args.json)

    # Generate HTML report
    reporter = ReportGenerator(
        results=scanner.results,
        metadata=scanner.scan_metadata,
        min_severity=args.min_severity,
    )
    reporter.save_html(args.output)

    # Print summary
    summary = scanner.summary()
    print("\n── Vulnerability Summary ──────────────────────────")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]:
        bar = "█" * summary[sev]
        print(f"  {sev:<8} {summary[sev]:>4}  {bar}")
    print(f"\nReport saved → {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
