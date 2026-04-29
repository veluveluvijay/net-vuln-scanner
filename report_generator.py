#!python3
"""
net-vuln-scanner/report_generator.py
Generates a polished, self-contained HTML vulnerability report.
"""

import html
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("report_generator")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]

SEVERITY_CSS = {
    "CRITICAL": ("#ff2d55", "#3d0010"),
    "HIGH":     ("#ff6b35", "#2d1000"),
    "MEDIUM":   ("#ffd60a", "#2d2000"),
    "LOW":      ("#30d158", "#00200d"),
    "NONE":     ("#636366", "#1c1c1e"),
}

SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


def _severity_rank(sev: str) -> int:
    return SEV_RANK.get(sev, 99)


def _meets_min(sev: str, min_sev: str) -> bool:
    return _severity_rank(sev) <= _severity_rank(min_sev)


def _e(text) -> str:
    """HTML-escape a value."""
    return html.escape(str(text))


class ReportGenerator:
    """
    Generates a self-contained HTML report from scan results.

    Parameters
    
    results     : Dict of {ip: host_data} as returned by NetworkScanner.run()
    metadata    : Scan metadata dict from NetworkScanner.scan_metadata
    min_severity: Minimum severity to include in the report
    """

    def __init__(self, results: dict, metadata: dict, min_severity: str = "LOW"):
        self.results = results
        self.metadata = metadata
        self.min_severity = min_severity

    def save_html(self, path: str) -> None:
        html_content = self._build_html()
        Path(path).write_text(html_content, encoding="utf-8")
        logger.info("HTML report saved to %s", path)

    #HTML Construction

    def _build_html(self) -> str:
        summary = self._compute_summary()
        host_cards = "\n".join(self._render_host(ip, data) for ip, data in self.results.items())
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Scan Report — {_e(self.metadata.get('target',''))} — {_e(self.metadata.get('timestamp',''))}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Space+Grotesk:wght@300;400;600;700&display=swap" rel="stylesheet">
  <style>
    /* Reset & Base  */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    :root {{
      --bg:        #0a0a0f;
      --surface:   #111118;
      --card:      #16161f;
      --border:    #2a2a3a;
      --text:      #e2e2f0;
      --muted:     #7070a0;
      --accent:    #6e6aff;
      --mono:      'JetBrains Mono', monospace;
      --sans:      'Space Grotesk', sans-serif;
      --r-sm:      6px;
      --r-md:      10px;
      --r-lg:      16px;
    }}
    html {{ scroll-behavior: smooth; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
    }}

    /* Scrollbar */
    ::-webkit-scrollbar {{ width: 6px; }}
    ::-webkit-scrollbar-track {{ background: var(--bg); }}
    ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}

    /* Layout */
    .container {{ max-width: 1200px; margin: 0 auto; padding: 0 24px 80px; }}

    /* Header  */
    header {{
      border-bottom: 1px solid var(--border);
      background: linear-gradient(135deg, #0d0d16 0%, #0a0a14 100%);
      position: sticky; top: 0; z-index: 100;
      backdrop-filter: blur(12px);
    }}
    .header-inner {{
      max-width: 1200px; margin: 0 auto;
      padding: 18px 24px;
      display: flex; align-items: center; justify-content: space-between;
      gap: 16px; flex-wrap: wrap;
    }}
    .logo {{
      display: flex; align-items: center; gap: 10px;
    }}
    .logo-icon {{
      width: 36px; height: 36px;
      background: linear-gradient(135deg, var(--accent), #a78bfa);
      border-radius: var(--r-sm);
      display: flex; align-items: center; justify-content: center;
      font-size: 18px;
    }}
    .logo-text {{ font-family: var(--mono); font-size: 13px; font-weight: 600; letter-spacing: 0.5px; }}
    .logo-sub {{ color: var(--muted); font-size: 11px; }}
    .header-meta {{ font-family: var(--mono); font-size: 11px; color: var(--muted); text-align: right; }}
    .header-meta span {{ color: var(--text); }}

    /* Hero */
    .hero {{
      padding: 56px 0 40px;
      position: relative;
    }}
    .hero::before {{
      content: '';
      position: absolute; top: 0; left: -24px; right: -24px; bottom: 0;
      background: radial-gradient(ellipse 60% 40% at 50% 0%, rgba(110,106,255,.08) 0%, transparent 70%);
      pointer-events: none;
    }}
    .hero-label {{
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: 12px;
    }}
    .hero h1 {{
      font-size: 32px;
      font-weight: 700;
      letter-spacing: -0.5px;
      line-height: 1.2;
      margin-bottom: 8px;
    }}
    .hero h1 .target {{
      font-family: var(--mono);
      color: var(--accent);
      font-size: 28px;
    }}
    .hero-meta {{
      display: flex; flex-wrap: wrap; gap: 24px;
      margin-top: 20px;
    }}
    .meta-chip {{
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
    }}
    .meta-chip span {{ color: var(--text); margin-left: 4px; }}

    /*  Summary Cards  */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin: 36px 0;
    }}
    .summary-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--r-md);
      padding: 20px 16px;
      text-align: center;
      position: relative;
      overflow: hidden;
      transition: transform .15s, border-color .15s;
    }}
    .summary-card:hover {{ transform: translateY(-2px); }}
    .summary-card::before {{
      content: '';
      position: absolute; top: 0; left: 0; right: 0; height: 3px;
    }}
    .summary-card.CRITICAL::before {{ background: #ff2d55; }}
    .summary-card.HIGH::before     {{ background: #ff6b35; }}
    .summary-card.MEDIUM::before   {{ background: #ffd60a; }}
    .summary-card.LOW::before      {{ background: #30d158; }}
    .summary-card.NONE::before     {{ background: #636366; }}
    .summary-card.hosts::before    {{ background: var(--accent); }}

    .card-count {{
      font-family: var(--mono);
      font-size: 36px;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 4px;
    }}
    .summary-card.CRITICAL .card-count {{ color: #ff2d55; }}
    .summary-card.HIGH .card-count     {{ color: #ff6b35; }}
    .summary-card.MEDIUM .card-count   {{ color: #ffd60a; }}
    .summary-card.LOW .card-count      {{ color: #30d158; }}
    .summary-card.NONE .card-count     {{ color: #636366; }}
    .summary-card.hosts .card-count    {{ color: var(--accent); }}
    .card-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }}

    /* Section Title */
    .section-title {{
      font-family: var(--mono);
      font-size: 11px;
      letter-spacing: 2px;
      text-transform: uppercase;
      color: var(--muted);
      margin: 40px 0 16px;
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .section-title::after {{
      content: '';
      flex: 1;
      height: 1px;
      background: var(--border);
    }}

    /*  Host Card  */
    .host-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: var(--r-lg);
      margin-bottom: 20px;
      overflow: hidden;
    }}
    .host-header {{
      padding: 16px 20px;
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      cursor: pointer;
      user-select: none;
    }}
    .host-header:hover {{ background: #1a1a28; }}
    .host-status {{
      width: 8px; height: 8px; border-radius: 50%;
      background: #30d158;
      box-shadow: 0 0 6px #30d158;
      flex-shrink: 0;
    }}
    .host-status.down {{ background: #636366; box-shadow: none; }}
    .host-ip {{
      font-family: var(--mono);
      font-size: 15px;
      font-weight: 600;
    }}
    .host-name {{
      font-size: 12px;
      color: var(--muted);
      font-family: var(--mono);
    }}
    .host-tags {{
      display: flex; gap: 6px; margin-left: auto; flex-wrap: wrap;
    }}
    .tag {{
      font-family: var(--mono);
      font-size: 10px;
      padding: 2px 8px;
      border-radius: 99px;
      border: 1px solid;
    }}
    .tag.ports {{ border-color: var(--accent); color: var(--accent); }}
    .tag.os    {{ border-color: var(--border); color: var(--muted); }}
    .chevron {{ margin-left: 8px; color: var(--muted); font-size: 12px; transition: transform .2s; }}
    .host-card.open .chevron {{ transform: rotate(180deg); }}

    .host-body {{ display: none; padding: 20px; }}
    .host-card.open .host-body {{ display: block; }}

    /*  Port Table  */
    .port-table-wrap {{ overflow-x: auto; margin-bottom: 20px; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }}
    th {{
      font-family: var(--mono);
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: var(--muted);
      text-align: left;
      padding: 8px 12px;
      border-bottom: 1px solid var(--border);
    }}
    td {{
      padding: 10px 12px;
      border-bottom: 1px solid rgba(42,42,58,.5);
      vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(110,106,255,.04); }}
    .port-num {{ font-family: var(--mono); font-weight: 600; color: var(--accent); }}
    .proto {{ font-family: var(--mono); font-size: 10px; color: var(--muted); }}
    .service-name {{ font-weight: 600; }}
    .version {{ font-family: var(--mono); font-size: 11px; color: var(--muted); }}

    /* CVE Badges */
    .cve-list {{ display: flex; flex-direction: column; gap: 4px; }}
    .cve-badge {{
      display: inline-flex; align-items: center; gap: 6px;
      font-family: var(--mono);
      font-size: 10px;
      padding: 3px 8px;
      border-radius: var(--r-sm);
      border: 1px solid;
      text-decoration: none;
      white-space: nowrap;
      width: fit-content;
      transition: opacity .15s;
    }}
    .cve-badge:hover {{ opacity: .75; }}
    .cve-badge.CRITICAL {{ border-color: #ff2d5560; color: #ff2d55; background: #ff2d5510; }}
    .cve-badge.HIGH     {{ border-color: #ff6b3560; color: #ff6b35; background: #ff6b3510; }}
    .cve-badge.MEDIUM   {{ border-color: #ffd60a60; color: #ffd60a; background: #ffd60a10; }}
    .cve-badge.LOW      {{ border-color: #30d15860; color: #30d158; background: #30d15810; }}
    .cve-badge.NONE     {{ border-color: #63636660; color: #636366; background: #63636610; }}
    .cve-score {{ font-weight: 700; }}

    /*  CVE Detail Panel  */
    .cve-details {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--r-md);
      padding: 16px;
      margin-top: 8px;
      font-size: 12px;
    }}
    .cve-details-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }}
    .cve-id {{
      font-family: var(--mono);
      font-weight: 700;
      font-size: 13px;
    }}
    .cve-desc {{
      color: var(--muted);
      line-height: 1.6;
      margin-bottom: 10px;
      font-size: 12px;
    }}
    .cve-refs {{ display: flex; flex-wrap: wrap; gap: 6px; }}
    .ref-link {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--accent);
      text-decoration: none;
      border: 1px solid var(--accent)40;
      padding: 2px 8px;
      border-radius: var(--r-sm);
    }}
    .ref-link:hover {{ background: var(--accent)15; }}

    /* OS Section */
    .os-section {{ margin-bottom: 16px; }}
    .os-match {{
      display: inline-block;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--r-sm);
      padding: 3px 10px;
      margin: 2px;
    }}
    .os-match .acc {{ color: var(--text); margin-left: 6px; }}

    /*  No Vuln State  */
    .no-cves {{
      font-family: var(--mono);
      font-size: 11px;
      color: #30d158;
      opacity: .7;
    }}

    /* Footer  */
    footer {{
      border-top: 1px solid var(--border);
      margin-top: 60px;
      padding: 24px 0;
      text-align: center;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--muted);
    }}
    footer a {{ color: var(--accent); text-decoration: none; }}

    /* Severity Badge (standalone) */
    .sev {{
      display: inline-block;
      font-family: var(--mono);
      font-size: 10px;
      font-weight: 700;
      padding: 2px 8px;
      border-radius: 4px;
      letter-spacing: .5px;
    }}
    .sev.CRITICAL {{ background: #ff2d5520; color: #ff2d55; }}
    .sev.HIGH     {{ background: #ff6b3520; color: #ff6b35; }}
    .sev.MEDIUM   {{ background: #ffd60a20; color: #ffd60a; }}
    .sev.LOW      {{ background: #30d15820; color: #30d158; }}
    .sev.NONE     {{ background: #63636620; color: #636366; }}

    /* Disclaimer Banner */
    .disclaimer {{
      background: #1a0a00;
      border: 1px solid #ff6b3540;
      border-radius: var(--r-md);
      padding: 14px 18px;
      font-size: 12px;
      color: #ff6b35;
      margin-top: 32px;
      font-family: var(--mono);
      line-height: 1.5;
    }}
    .disclaimer strong {{ display: block; margin-bottom: 4px; }}

    @media (max-width: 600px) {{
      .hero h1 {{ font-size: 22px; }}
      .hero h1 .target {{ font-size: 18px; }}
    }}
  </style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="logo">
      <div class="logo-icon">🛡</div>
      <div>
        <div class="logo-text">NET-VULN-SCANNER</div>
        <div class="logo-sub">Automated Vulnerability Assessment</div>
      </div>
    </div>
    <div class="header-meta">
      Generated <span>{_e(self.metadata.get('timestamp',''))}</span><br>
      Duration <span>{_e(self.metadata.get('duration_seconds',''))}s</span>
    </div>
  </div>
</header>

<div class="container">

  <div class="hero">
    <div class="hero-label">// scan report</div>
    <h1>Vulnerability Assessment<br><span class="target">{_e(self.metadata.get('target',''))}</span></h1>
    <div class="hero-meta">
      <div class="meta-chip">HOSTS UP<span>{_e(self.metadata.get('hosts_up',''))}</span></div>
      <div class="meta-chip">TOTAL HOSTS<span>{_e(self.metadata.get('total_hosts',''))}</span></div>
      <div class="meta-chip">SCAN ARGS<span>{_e(self.metadata.get('scan_args',''))}</span></div>
      <div class="meta-chip">MIN SEVERITY<span>{_e(self.min_severity)}</span></div>
    </div>
  </div>

  {self._render_summary_cards()}

  <div class="disclaimer">
    <strong>⚠ AUTHORIZED USE ONLY</strong>
    This report is generated from an authorized security assessment.
    Unauthorised network scanning is illegal. This tool must only be used on systems
    you own or have explicit written permission to test. Refer to the project README
    for the full legal disclaimer.
  </div>

  <div class="section-title">Host Details</div>

  {host_cards}

</div>

<footer>
  <div class="container">
    net-vuln-scanner &nbsp;·&nbsp; CVE data sourced from
    <a href="https://nvd.nist.gov/" target="_blank" rel="noopener">NIST NVD</a>
    &nbsp;·&nbsp; Scan engine: <a href="https://nmap.org/" target="_blank" rel="noopener">Nmap</a>
    &nbsp;·&nbsp; For authorized security testing only
  </div>
</footer>

<script>
  // Collapsible host cards
  document.querySelectorAll('.host-header').forEach(h => {{
    h.addEventListener('click', () => {{
      h.closest('.host-card').classList.toggle('open');
    }});
  }});
  // Auto-open cards with findings
  document.querySelectorAll('.host-card').forEach(card => {{
    if (card.querySelector('.cve-badge')) card.classList.add('open');
  }});
</script>

</body>
</html>"""

    #Summary Cards 

    def _compute_summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        for host in self.results.values():
            for port in host.get("ports", []):
                for cve in port.get("cves", []):
                    sev = cve.get("severity", "NONE")
                    if _meets_min(sev, self.min_severity):
                        counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _render_summary_cards(self) -> str:
        summary = self._compute_summary()
        hosts_up = self.metadata.get("hosts_up", 0)
        total = self.metadata.get("total_hosts", 0)
        cards = f"""
    <div class="summary-grid">
      <div class="summary-card hosts">
        <div class="card-count">{_e(hosts_up)}/{_e(total)}</div>
        <div class="card-label">Hosts Up</div>
      </div>"""
        for sev in SEVERITY_ORDER[:-1]:
            cards += f"""
      <div class="summary-card {sev}">
        <div class="card-count">{summary[sev]}</div>
        <div class="card-label">{sev}</div>
      </div>"""
        cards += "\n    </div>"
        return cards

    #Host Rendering 

    def _render_host(self, ip: str, data: dict) -> str:
        state = data.get("state", "unknown")
        hostname = data.get("hostname", ip)
        ports = data.get("ports", [])
        os_matches = data.get("os_matches", [])

        port_count_tag = f'<span class="tag ports">{len(ports)} port{"s" if len(ports) != 1 else ""}</span>'
        os_tag = ""
        if os_matches:
            os_name = os_matches[0]["name"][:30]
            os_tag = f'<span class="tag os">{_e(os_name)}</span>'

        os_section = ""
        if os_matches:
            badges = " ".join(
                f'<span class="os-match">{_e(o["name"])}<span class="acc">{_e(o["accuracy"])}%</span></span>'
                for o in os_matches
            )
            os_section = f'<div class="os-section">{badges}</div>'

        port_rows = "\n".join(self._render_port_row(p) for p in ports)
        port_table = f"""
      {os_section}
      <div class="port-table-wrap">
        <table>
          <thead>
            <tr>
              <th>Port</th>
              <th>Service</th>
              <th>Product / Version</th>
              <th>CVEs</th>
            </tr>
          </thead>
          <tbody>
            {port_rows if port_rows else '<tr><td colspan="4" class="no-cves">No open ports discovered</td></tr>'}
          </tbody>
        </table>
      </div>"""

        status_class = "" if state == "up" else " down"
        return f"""
  <div class="host-card">
    <div class="host-header">
      <div class="host-status{status_class}"></div>
      <div class="host-ip">{_e(ip)}</div>
      {f'<div class="host-name">{_e(hostname)}</div>' if hostname != ip else ''}
      <div class="host-tags">{port_count_tag}{os_tag}</div>
      <div class="chevron">▼</div>
    </div>
    <div class="host-body">
      {port_table}
    </div>
  </div>"""

    def _render_port_row(self, port: dict) -> str:
        cves = [
            c for c in port.get("cves", [])
            if _meets_min(c.get("severity", "NONE"), self.min_severity)
        ]
        cves_sorted = sorted(cves, key=lambda c: c.get("cvss_score", 0), reverse=True)

        cve_cells = ""
        if cves_sorted:
            badges = []
            for cve in cves_sorted[:8]:
                sev = cve.get("severity", "NONE")
                score = cve.get("cvss_score", 0)
                cve_id = cve.get("id", "")
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                desc_short = _e(cve.get("description", "")[:120])
                refs_html = "".join(
                    f'<a class="ref-link" href="{_e(r)}" target="_blank" rel="noopener">ref ↗</a>'
                    for r in cve.get("references", [])[:3]
                )
                badges.append(f"""
                  <a class="cve-badge {sev}" href="{_e(url)}" target="_blank" rel="noopener">
                    <span class="cve-score">{score:.1f}</span>
                    <span class="sev {sev}">{sev}</span>
                    {_e(cve_id)}
                  </a>
                  <div class="cve-details" style="display:none" id="detail-{_e(cve_id)}">
                    <div class="cve-details-header">
                      <span class="cve-id">{_e(cve_id)}</span>
                      <span class="sev {sev}">{sev}</span>
                      <span style="font-family:var(--mono);font-size:11px;color:var(--muted)">CVSS {score:.1f}</span>
                    </div>
                    <div class="cve-desc">{desc_short}{'…' if len(cve.get('description','')) > 120 else ''}</div>
                    <div class="cve-refs">{refs_html}</div>
                  </div>""")

            cve_cells = f'<div class="cve-list">{"".join(badges)}</div>'
        else:
            cve_cells = '<span class="no-cves">✓ No CVEs matched</span>'

        product = port.get("product", "")
        version = port.get("version", "")
        extra = port.get("extra_info", "")
        prod_str = product
        if version:
            prod_str += f" {version}"
        if extra:
            prod_str += f" ({extra})"

        return f"""
            <tr>
              <td>
                <span class="port-num">{_e(port['port'])}</span>
                <span class="proto">/{_e(port['protocol'])}</span>
              </td>
              <td><span class="service-name">{_e(port.get('service','unknown'))}</span></td>
              <td><span class="version">{_e(prod_str) if prod_str else '—'}</span></td>
              <td>{cve_cells}</td>
            </tr>"""
