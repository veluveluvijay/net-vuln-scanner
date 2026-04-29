# 🛡️ net-vuln-scanner

## 📊 Live Sample Report
👉 [Click here to view a live vulnerability scan report](https://veluveluvijay.github.io/net-vuln-scanner/sample_report.html)

**Automated Network Vulnerability Scanner** — wraps Nmap for host/port/service discovery and queries the [NIST National Vulnerability Database (NVD)](https://nvd.nist.gov/) to match discovered services against known CVEs. Generates polished, self-contained HTML reports with severity ratings and supports scheduled scanning via cron or Windows Task Scheduler.

> **⚠ IMPORTANT:** This tool is for **authorized security testing only**. Read the [Legal & Ethical Use](#️-legal--ethical-use) section before proceeding.

---

## Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Scheduled Scanning](#-scheduled-scanning)
- [Report Format](#-report-format)
- [Sample Output](#-sample-output)
- [NVD API Setup](#-nvd-api-setup)
- [Configuration Reference](#-configuration-reference)
- [Project Structure](#-project-structure)
- [Legal & Ethical Use](#️-legal--ethical-use)
- [Contributing](#-contributing)

---

##Features

| Feature | Details |
|---|---|
| **Nmap Integration** | Service version detection (`-sV`), script scanning (`-sC`), OS fingerprinting |
| **NVD CVE Matching** | CPE-based lookups + keyword fallback via NVD 2.0 REST API |
| **CVSS Severity Ratings** | Critical / High / Medium / Low bands from CVSS v3.1 scores |
| **HTML Reports** | Self-contained, dark-themed report with collapsible host cards |
| **JSON Export** | Raw results as JSON for downstream processing / SIEMs |
| **Scheduled Scans** | Cross-platform: `cron` (Linux/macOS) and Windows Task Scheduler |
| **Rate-Limit Handling** | Automatic back-off on NVD 429 responses; in-memory caching |
| **Min-Severity Filter** | Filter report to Critical-only, High+, etc. |
| **Ethical Gate** | Interactive confirmation prompt before every scan |

---

##Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     net-vuln-scanner                            │
│                                                                 │
│  ┌──────────┐    ┌─────────────────────────────────────────┐   │
│  │          │    │             scanner.py                  │   │
│  │ scheduler│───▶│  CLI entry point · orchestration loop   │   │
│  │  .py     │    └──────────┬──────────────┬───────────────┘   │
│  └──────────┘               │              │                   │
│                             ▼              ▼                   │
│               ┌─────────────────┐  ┌───────────────────────┐  │
│               │  NetworkScanner │  │    ReportGenerator    │  │
│               │  (nmap wrapper) │  │  (HTML report engine) │  │
│               └────────┬────────┘  └───────────────────────┘  │
│                        │                                       │
│              ┌─────────┴──────────┐                           │
│              ▼                    ▼                           │
│   ┌──────────────────┐  ┌──────────────────────┐             │
│   │  python-nmap     │  │     NVDClient         │             │
│   │                  │  │  (nvd_client.py)      │             │
│   │  Nmap subprocess │  │  Rate-limit aware     │             │
│   │  XML parser      │  │  In-memory cache      │             │
│   └────────┬─────────┘  └──────────┬────────────┘            │
│            │                       │                          │
└────────────┼───────────────────────┼──────────────────────────┘
             ▼                       ▼
    ┌──────────────────┐   ┌─────────────────────────┐
    │   Nmap binary    │   │  NIST NVD REST API 2.0   │
    │   (system)       │   │  nvd.nist.gov            │
    └──────────────────┘   └─────────────────────────┘

Data Flow:
  Target → Nmap scan → Host/Port/CPE data
       → NVD API lookup (CPE / keyword)
       → CVE list with CVSS scores
       → HTML Report + optional JSON export
```

### Component Responsibilities

| File | Responsibility |
|---|---|
| `scanner.py` | CLI, orchestration, Nmap invocation, CVE enrichment loop |
| `nvd_client.py` | NVD 2.0 REST API client, rate limiting, response parsing, caching |
| `report_generator.py` | Self-contained HTML report builder with severity colour-coding |
| `scheduler.py` | Cross-platform cron / Task Scheduler integration |

---

## Requirements

### System

- **Python 3.9+**
- **[Nmap](https://nmap.org/download.html) 7.80+** installed and on `PATH`
  - Linux: `sudo apt install nmap` / `sudo dnf install nmap`
  - macOS: `brew install nmap`
  - Windows: [nmap.org installer](https://nmap.org/download.html)
- Root / Administrator privileges for SYN scans (`-sS`); TCP connect scans work without elevation

### Python Packages

```
python-nmap>=0.7.1
requests>=2.31.0
python-dotenv>=1.0.0   # optional, for .env loading
```

---

## Installation

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/net-vuln-scanner.git
cd net-vuln-scanner

# 2. Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Set your NVD API key
cp .env.example .env
# Edit .env and add your key:  NVD_API_KEY=<your_key>

# 5. Verify Nmap is available
nmap --version
```

---

## Quick Start

```bash
# Scan a single host (TCP connect scan, no root required)
python scanner.py --target 192.168.1.1

# Scan a /24 subnet
python scanner.py --target 192.168.1.0/24

# Specify ports and output path
python scanner.py --target 10.0.0.0/24 --ports 22,80,443,3306,8080 --output reports/scan.html

# Save raw JSON too
python scanner.py --target 192.168.1.0/24 --output report.html --json results.json

# Filter to High/Critical CVEs only
python scanner.py --target 10.0.0.1 --min-severity HIGH --output critical_report.html
```

You will be prompted to confirm authorization before the scan begins:

```
============================================================
 AUTOMATED NETWORK VULNERABILITY SCANNER
============================================================
 Target : 192.168.1.0/24
 Ports  : top-1000 (nmap default)
 Output : report.html
============================================================

⚠  WARNING: Only scan networks and systems you OWN or have
   EXPLICIT WRITTEN PERMISSION to test. Unauthorized scanning
   is illegal and unethical. By continuing you confirm you
   have proper authorization.

Type 'YES' to proceed:
```

---

## Usage Examples

### Basic Single Host

```bash
python scanner.py --target 192.168.1.100
```

### Subnet Sweep with Custom Ports

```bash
python scanner.py 
  --target 10.0.0.0/24 
  --ports 21,22,23,25,53,80,110,443,445,3306,3389,8080,8443 
  --output reports/$(date +%Y%m%d)_scan.html
```

### Aggressive Scan (requires root/Administrator)

```bash
sudo python scanner.py 
  --target 192.168.1.0/24 
  --scan-args "-sS -sV -sC -O --open -T4" 
  --output report.html
```

### Stealth / Slow Scan (IDS-friendly)

```bash
python scanner.py 
  --target 10.0.0.1 
  --scan-args "-sV --open -T2 --max-rtt-timeout 500ms" 
  --output report.html
```

### Critical Only Report

```bash
python scanner.py 
  --target 172.16.0.0/24 
  --min-severity CRITICAL 
  --output critical_only.html
```

### With NVD API Key (via CLI)

```bash
python scanner.py 
  --target 192.168.1.0/24 
  --nvd-api-key "YOUR-API-KEY-HERE" 
  --output report.html
```

### Export JSON for SIEM Integration

```bash
python scanner.py 
  --target 192.168.1.0/24 
  --output report.html 
  --json /var/log/vuln-scans/$(hostname)_$(date +%Y%m%d).json
```


## Scheduled Scanning

The `scheduler.py` tool wraps cron (Linux/macOS) and Windows Task Scheduler.

### Linux / macOS — Cron

```bash
# Daily at 02:00 AM
python scheduler.py install 
  --target 192.168.1.0/24 
  --frequency daily 
  --time 02:00

# Weekly on Monday at 03:30 AM
python scheduler.py install 
  --target 10.0.0.0/24 
  --frequency weekly 
  --day monday 
  --time 03:30

# List all scheduled net-vuln-scanner jobs
python scheduler.py list

# Remove job for a target
python scheduler.py remove --target 192.168.1.0/24

# Run immediately (no scheduling)
python scheduler.py run --target 192.168.1.0/24
```

Generated crontab entry example:

```cron
0 2 * * * echo YES | /usr/bin/python3 /opt/net-vuln-scanner/scanner.py 
  --target 192.168.1.0/24 
  --output /opt/net-vuln-scanner/reports/scan_192_168_1_0_24_$(date +%Y%m%d_%H%M%S).html 
  # NET-VULN-SCANNER target=192.168.1.0/24
```

### Windows — Task Scheduler

```powershell
# Daily at 02:00
python scheduler.py install 
  --target 192.168.1.0/24 
  --frequency daily 
  --time 02:00

# Weekly on Wednesday
python scheduler.py install 
  --target 10.0.0.0/24 
  --frequency weekly 
  --day wednesday 
  --time 03:00

# List / Remove
python scheduler.py list
python scheduler.py remove --target 192.168.1.0/24
```

Reports are saved automatically to `reports/` with timestamps in the filename.

---

## Report Format

The HTML report is **self-contained** (single `.html` file, no external assets required after page load).

### Report Sections

1. **Header** — Target, timestamp, scan duration (sticky navigation bar)
2. **Summary Cards** — CVE counts by severity + hosts-up/total
3. **Ethical Disclaimer Banner**
4. **Host Cards** (collapsible)
   - Host IP, reverse hostname, state indicator
   - OS fingerprint matches with accuracy percentages
   - Open ports table: port/protocol, service, product/version, matched CVEs
   - Per-CVE badges: CVSS score, severity band, CVE ID (links to NVD)

### Severity Color Coding

| Severity | CVSS Range | Color |
|---|---|---|
| CRITICAL | 9.0 – 10.0 | 🔴 Red |
| HIGH | 7.0 – 8.9 | 🟠 Orange |
| MEDIUM | 4.0 – 6.9 | 🟡 Yellow |
| LOW | 0.1 – 3.9 | 🟢 Green |
| NONE | 0.0 | ⚫ Gray |

---

## 📸 Sample Output

### CLI Summary

```
── Vulnerability Summary ──────────────────────────
  CRITICAL    3  ███
  HIGH        8  ████████
  MEDIUM     14  ██████████████
  LOW         5  █████
  NONE       22  ██████████████████████

Report saved → reports/scan_20241115_020301.html
```

### JSON Output Structure

```json
{
  "metadata": {
    "target": "192.168.1.0/24",
    "scan_args": "-sV -sC --open -T4 --host-timeout 60s",
    "timestamp": "2024-11-15T02:03:01Z",
    "duration_seconds": 47.3,
    "hosts_up": 12,
    "total_hosts": 256
  },
  "hosts": {
    "192.168.1.1": {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "state": "up",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "service": "http",
          "product": "lighttpd",
          "version": "1.4.45",
          "cpes": ["cpe:/a:lighttpd:lighttpd:1.4.45"],
          "cves": [
            {
              "id": "CVE-2022-22707",
              "description": "In lighttpd 1.4.46 through 1.4.63...",
              "cvss_score": 7.5,
              "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
              "severity": "HIGH",
              "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22707"],
              "published": "2022-01-06T00:00:00.000",
              "modified": "2022-01-11T00:00:00.000"
            }
          ]
        }
      ],
      "os_matches": [
        { "name": "Linux 4.15", "accuracy": "94" }
      ]
    }
  }
}
```

---

##  NVD API Setup

The NVD Public API has rate limits:

| Auth Level | Rate Limit |
|---|---|
| No API key | 5 requests / 30 seconds |
| With API key | 50 requests / 30 seconds |

For scanning large subnets, an API key is **strongly recommended**.

1. Visit [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
2. Fill in the form (email required)
3. Check your email for the key
4. Add it to `.env`:

```ini
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Or pass it at runtime:

```bash
python scanner.py --target 192.168.1.0/24 --nvd-api-key "YOUR-KEY"
```

---

## ⚙️ Configuration Reference

### `scanner.py` Arguments

| Argument | Default | Description |
|---|---|---|
| `--target` | *(required)* | IP, CIDR subnet, or hostname |
| `--ports` | top-1000 | Port list: `22,80,443` or `1-1024` |
| `--scan-args` | `-sV -sC --open -T4 --host-timeout 60s` | Raw Nmap arguments |
| `--output` | `report.html` | HTML report output path |
| `--json` | *(none)* | Also save raw JSON results |
| `--nvd-api-key` | `$NVD_API_KEY` | NVD 2.0 API key |
| `--min-severity` | `LOW` | Minimum severity to include in report |
| `--verbose` / `-v` | off | Enable DEBUG logging |

### `scheduler.py` Arguments

| Sub-command | Key Arguments |
|---|---|
| `install` | `--target`, `--frequency` {hourly,daily,weekly,monthly}, `--time` HH:MM, `--day` |
| `remove` | `--target` |
| `list` | *(none)* |
| `run` | `--target`, `--extra-args` |

---

## 📁 Project Structure

```
net-vuln-scanner/
├── scanner.py           # Main CLI tool
├── nvd_client.py        # NVD 2.0 API client
├── report_generator.py  # HTML report engine
├── scheduler.py         # Cron / Task Scheduler integration
├── requirements.txt     # Python dependencies
├── .env.example         # Environment variable template
├── .gitignore
├── LICENSE
├── README.md
└── reports/             # Output directory (auto-created)
    └── *.html
```

---

## ⚖️ Legal & Ethical Use

### Authorization Requirement

**You MUST have explicit, written authorization before scanning any network or host.**

This includes:
- Networks and devices you own personally
- Corporate networks where you hold a current, signed penetration testing agreement
- Lab environments and CTF/practice ranges explicitly designated for testing
- Cloud instances you control (check your provider's scanning policy — AWS, Azure, GCP each have specific requirements)

### What Constitutes Unauthorized Scanning

Scanning without authorization may violate:

- **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **European Union**: Directive on Attacks Against Information Systems (2013/40/EU); national implementations vary by member state
- **United Kingdom**: Computer Misuse Act 1990
- **Australia**: Criminal Code Act 1995, Part 10.7
- **Canada**: Criminal Code, Section 342.1

Even passive or informational scans (SYN probes, service fingerprinting) can constitute unauthorized access under these laws.

### Scope Definition Best Practices

Before scanning, document in writing:

1. **Target IP ranges / hostnames** — be specific; avoid scope creep
2. **Authorized scan types** — SYN, TCP connect, UDP, service detection, OS fingerprinting
3. **Authorized time windows** — avoid business hours where possible
4. **Emergency contact** — who to notify if systems are impacted
5. **Data handling** — how scan results and CVE data will be stored and shared
6. **Report recipients** — who receives vulnerability findings

### Responsible Disclosure

If you discover vulnerabilities in systems you legitimately test:

1. Document findings thoroughly (this tool generates the report)
2. Notify the system owner privately and promptly
3. Allow a reasonable remediation window (typically 90 days)
4. Follow coordinated disclosure principles (see [CERT/CC](https://www.kb.cert.org/vuls/govdisclosure/), [ISO/IEC 29147](https://www.iso.org/standard/72311.html))
5. Do **not** publicly disclose before the owner has had time to patch

### Disclaimer

> This software is provided for **educational and authorized security testing purposes only**.
> The authors and contributors accept **no liability** for misuse, damage, or legal consequences
> arising from use of this tool. By using net-vuln-scanner, you agree that you are solely
> responsible for ensuring you have proper authorization for every scan you conduct.

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m "feat: add my feature"`
4. Push: `git push origin feature/my-feature`
5. Open a Pull Request

### Ideas for Contribution

- [ ] PDF report export (using `weasyprint` or `pdfkit`)
- [ ] Slack / email notifications on Critical findings
- [ ] SQLite persistence for trend analysis across scans
- [ ] Docker container with Nmap pre-installed
- [ ] CVE delta report (new findings since last scan)
- [ ] Integration with Shodan / Censys APIs

---

## License

MIT License — see `LICENSE` for details.

CVE data is sourced from the [NIST National Vulnerability Database](https://nvd.nist.gov/).
NVD data is publicly available but subject to [NVD usage terms](https://nvd.nist.gov/general/FAQ-resultsDelivery).
