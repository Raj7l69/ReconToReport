"""
report/generator.py
Builds the findings into Markdown, JSON, HTML, and (optionally) PDF reports.
"""

import json
from pathlib import Path
from datetime import datetime
from utils.logger import get_logger

log = get_logger("report")

SEVERITY_COLORS = {
    "Critical": "#7a1414",
    "High": "#c0392b",
    "Medium": "#d68910",
    "Low": "#2980b9",
    "Info": "#7f8c8d",
    "Unknown": "#7f8c8d",
    "None": "#95a5a6",
}


def build_markdown(target: str, services: list, enum_results: dict, findings: list) -> str:
    lines = []
    lines.append(f"# ReconToReport — Findings for `{target}`")
    lines.append(f"_Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n")

    lines.append("## Open Services")
    lines.append("| Port | Protocol | Service | Product | Version |")
    lines.append("|------|----------|---------|---------|---------|")
    for s in services:
        lines.append(f"| {s['port']} | {s['protocol']} | {s['service']} | {s.get('product','')} | {s.get('version','')} |")

    lines.append("\n## Vulnerability Findings — CVE Correlation (NVD, sorted by CVSS severity)")
    if not findings:
        lines.append("_No services with identifiable product/version to correlate._")
    else:
        lines.append("| Severity | CVSS | Port | Service | Product/Version | CVEs | Exploit-DB Matches |")
        lines.append("|----------|------|------|---------|------------------|------|---------------------|")
        for f in findings:
            score = f.get("top_cvss_score")
            score_str = f"{score:.1f}" if score is not None else "—"
            lines.append(
                f"| {f['severity']} | {score_str} | {f['port']} | {f['service']} | "
                f"{f['product']} {f['version']} | {f['cve_count']} | {f['exploit_count']} |"
            )

        lines.append("\n### CVE Detail")
        for f in findings:
            if not f.get("cve_matches"):
                continue
            lines.append(f"\n**Port {f['port']} — {f['product']} {f['version']}**")
            for cve in f["cve_matches"][:5]:
                score = cve.get("cvss_score")
                score_str = f"{score:.1f}" if score is not None else "—"
                lines.append(f"- `{cve['cve_id']}` (CVSS {score_str}, {cve['severity']}): {cve['description']}")

    lines.append("\n## Web Findings (OWASP basic probes)")
    web_findings_found = False
    for port, data in enum_results.items():
        if port == "dns" or not isinstance(data, dict):
            continue
        owasp = data.get("owasp_probes")
        if owasp and (owasp.get("sqli_findings") or owasp.get("xss_findings")):
            web_findings_found = True
            lines.append(f"\n**Port {port} — {data.get('url')}**")
            for f in owasp.get("sqli_findings", []):
                lines.append(f"- ⚠️ Possible SQLi on param `{f['param']}` (payload: `{f['payload']}`, matched: `{f['matched_signature']}`) — verify manually")
            for f in owasp.get("xss_findings", []):
                lines.append(f"- ⚠️ Reflected XSS on param `{f['param']}` — payload echoed unescaped, verify manually")
    if not web_findings_found:
        lines.append("_No SQLi/XSS reflection candidates found by the basic probes. Manual/deeper testing (sqlmap, Burp) still recommended._")

    if "dns" in enum_results and not enum_results["dns"].get("skipped"):
        dns = enum_results["dns"]
        lines.append("\n## DNS Enumeration")
        lines.append(f"- Nameservers: {', '.join(dns.get('nameservers', [])) or 'none found'}")
        for ns, zt in dns.get("zone_transfer", {}).items():
            if zt.get("transfer_successful"):
                lines.append(f"- ⚠️ **Zone transfer SUCCEEDED** against `{ns}` — misconfiguration, high-value finding")

    lines.append("\n## Raw Enumeration Output")
    for port, data in enum_results.items():
        lines.append(f"\n### {'DNS' if port == 'dns' else f'Port {port}'}")
        lines.append(f"```\n{json.dumps(data, indent=2, default=str)}\n```")

    return "\n".join(lines)


def build_plain_text(target: str, services: list, enum_results: dict, findings: list) -> str:
    """
    Same content as the Markdown report but stripped of Markdown syntax
    (#, |, ``` etc.) — for a report.txt that's readable directly in a
    terminal or a plain text editor without any rendering.
    """
    lines = []
    lines.append("=" * 70)
    lines.append(f"ReconToReport — Findings for {target}")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    lines.append("\nOPEN SERVICES\n" + "-" * 70)
    for s in services:
        lines.append(f"  Port {s['port']:<6} {s['protocol']:<4} {s['service']:<15} "
                      f"{s.get('product','')} {s.get('version','')}")

    lines.append("\nVULNERABILITY FINDINGS (NVD, sorted by severity)\n" + "-" * 70)
    if not findings:
        lines.append("  No services with identifiable product/version to correlate.")
    else:
        for f in findings:
            score = f.get("top_cvss_score")
            score_str = f"{score:.1f}" if score is not None else "-"
            epss = f.get("epss", {}).get("score")
            epss_str = f"EPSS {epss*100:.0f}%" if epss is not None else "EPSS -"
            kev_flag = " [KEV: ACTIVELY EXPLOITED]" if f.get("cisa_kev", {}).get("in_kev") else ""
            lines.append(f"  [{f['severity']:<8}] CVSS {score_str:<4} {epss_str:<9} Port {f['port']:<6} "
                         f"{f['service']:<10} {f['product']} {f['version']} "
                         f"| CVEs: {f['cve_count']} | Exploits: {f['exploit_count']}{kev_flag}")

    lines.append("\nWEB FINDINGS (OWASP basic probes)\n" + "-" * 70)
    web_found = False
    for port, data in enum_results.items():
        if port == "dns" or not isinstance(data, dict):
            continue
        owasp = data.get("owasp_probes")
        if owasp and (owasp.get("sqli_findings") or owasp.get("xss_findings")):
            web_found = True
            lines.append(f"  Port {port} — {data.get('url')}")
            for f in owasp.get("sqli_findings", []):
                lines.append(f"    ! Possible SQLi on param '{f['param']}' (payload: {f['payload']})")
            for f in owasp.get("xss_findings", []):
                lines.append(f"    ! Reflected XSS on param '{f['param']}'")
    if not web_found:
        lines.append("  No SQLi/XSS reflection candidates found. Manual testing still recommended.")

    lines.append("\n" + "=" * 70)
    lines.append("End of report.")
    return "\n".join(lines)


def build_cve_findings_file(target: str, findings: list) -> str:
    """
    A dedicated, CVE-only file: for every service, which CVE(s) matched,
    each CVE's description, CVSS score, and severity — separate from the
    main report so it can be handed off or grepped on its own.
    """
    lines = []
    lines.append(f"CVE FINDINGS — {target}")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    any_cves = False
    for f in findings:
        if not f.get("cve_matches"):
            continue
        any_cves = True
        top_cve_id = f.get("top_cve_id")
        lines.append(f"\nService : {f['service']} ({f['product']} {f['version']})")
        lines.append(f"Port    : {f['port']}")
        lines.append(f"Severity: {f['severity']} (highest CVSS for this service: "
                      f"{f['top_cvss_score'] if f['top_cvss_score'] is not None else 'N/A'}, "
                      f"from {top_cve_id or 'N/A'})")

        epss = f.get("epss", {})
        if epss.get("score") is not None:
            lines.append(f"EPSS    : {epss['score']:.2f} for {top_cve_id} "
                          f"({epss['score']*100:.0f}% chance of exploitation in the next 30 days)")

        kev = f.get("cisa_kev", {})
        if kev.get("in_kev"):
            lines.append(f"CISA KEV: *** {top_cve_id} — actively exploited in the wild "
                          f"(added: {kev.get('date_added', 'unknown date')}, "
                          f"ransomware use: {kev.get('ransomware_use', 'Unknown')}) ***")
        else:
            lines.append(f"CISA KEV: {top_cve_id} — not listed in CISA's Known Exploited Vulnerabilities catalog")

        lines.append("-" * 70)
        for cve in f["cve_matches"]:
            score = cve.get("cvss_score")
            score_str = f"{score:.1f}" if score is not None else "N/A"
            marker = "  <-- EPSS / CISA KEV / Vulners checked against THIS CVE" if cve["cve_id"] == top_cve_id else ""
            lines.append(f"  CVE ID     : {cve['cve_id']}{marker}")
            lines.append(f"  CVSS Score : {score_str}")
            lines.append(f"  Severity   : {cve['severity']}")
            lines.append(f"  Published  : {cve.get('published', 'N/A')}")
            lines.append(f"  Description: {cve['description']}")
            lines.append("")

        if f.get("vulners_exploits"):
            lines.append("  Exploit/PoC links (via Vulners):")
            for ve in f["vulners_exploits"]:
                lines.append(f"    - [{ve['source']}] {ve['title']} -> {ve['url']}")
            lines.append("")
        lines.append("=" * 70)

    if not any_cves:
        lines.append("\nNo CVEs matched for any detected service.")

    return "\n".join(lines)


def _esc(text) -> str:
    """Minimal HTML-escape for values interpolated into the template."""
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def build_html(target: str, services: list, enum_results: dict, findings: list) -> str:
    services_rows = "".join(
        f"<tr><td>{_esc(s['port'])}</td><td>{_esc(s['protocol'])}</td><td>{_esc(s['service'])}</td>"
        f"<td>{_esc(s.get('product',''))}</td><td>{_esc(s.get('version',''))}</td></tr>"
        for s in services
    )

    # Findings rows built below in the loop (with CVE detail sub-rows)
    findings_html_rows = []
    for f in findings:
        score = f.get("top_cvss_score")
        score_str = f"{score:.1f}" if score is not None else "—"
        color = SEVERITY_COLORS.get(f["severity"], "#999")
        cve_links = "".join(
            f"<div class='cve'><b>{_esc(c['cve_id'])}</b> (CVSS {c['cvss_score'] if c['cvss_score'] is not None else '—'}) "
            f"— {_esc(c['description'][:200])}</div>"
            for c in f.get("cve_matches", [])[:5]
        )
        findings_html_rows.append(f"""
        <tr style="border-left:4px solid {color}">
          <td><span class="badge" style="background:{color}">{_esc(f['severity'])}</span></td>
          <td>{score_str}</td>
          <td>{_esc(f['port'])}</td>
          <td>{_esc(f['service'])}</td>
          <td>{_esc(f['product'])} {_esc(f['version'])}</td>
          <td>{f['cve_count']}</td>
          <td>{f['exploit_count']}</td>
        </tr>
        <tr class="cve-detail"><td colspan="7">{cve_links or '<i>No CVE detail</i>'}</td></tr>
        """)

    web_findings_html = []
    for port, data in enum_results.items():
        if port == "dns" or not isinstance(data, dict):
            continue
        owasp = data.get("owasp_probes")
        if owasp and (owasp.get("sqli_findings") or owasp.get("xss_findings")):
            items = "".join(
                f"<li>⚠️ Possible SQLi on <code>{_esc(x['param'])}</code> "
                f"(payload <code>{_esc(x['payload'])}</code>)</li>"
                for x in owasp.get("sqli_findings", [])
            ) + "".join(
                f"<li>⚠️ Reflected XSS on <code>{_esc(x['param'])}</code></li>"
                for x in owasp.get("xss_findings", [])
            )
            web_findings_html.append(f"<h3>Port {_esc(port)} — {_esc(data.get('url'))}</h3><ul>{items}</ul>")

    screenshots_html = []
    for port, data in enum_results.items():
        if isinstance(data, dict) and data.get("screenshot_dir"):
            screenshots_html.append(
                f"<p>Screenshots for port {_esc(port)} saved to: <code>{_esc(data['screenshot_dir'])}</code></p>"
            )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ReconToReport — {_esc(target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 40px;
          background: #0f1117; color: #e6e6e6; }}
  h1 {{ color: #fff; }}
  h2 {{ border-bottom: 1px solid #333; padding-bottom: 8px; margin-top: 40px; }}
  table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #2a2d36; }}
  th {{ background: #1a1d27; }}
  .badge {{ color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 0.85em; font-weight: 600; }}
  .cve-detail td {{ background: #14161e; font-size: 0.9em; color: #ccc; padding-top: 0; }}
  .cve {{ margin: 4px 0; }}
  .meta {{ color: #888; font-size: 0.9em; }}
  code {{ background: #1a1d27; padding: 2px 6px; border-radius: 4px; }}
</style>
</head>
<body>
  <h1>🎯 ReconToReport — Findings for {_esc(target)}</h1>
  <p class="meta">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

  <h2>Open Services</h2>
  <table>
    <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
    {services_rows or '<tr><td colspan="5">No open services detected</td></tr>'}
  </table>

  <h2>Vulnerability Findings (NVD-correlated, sorted by severity)</h2>
  <table>
    <tr><th>Severity</th><th>CVSS</th><th>Port</th><th>Service</th><th>Product/Version</th><th>CVEs</th><th>Exploits</th></tr>
    {''.join(findings_html_rows) or '<tr><td colspan="7">No correlated findings</td></tr>'}
  </table>

  <h2>Web Findings (OWASP basic probes)</h2>
  {''.join(web_findings_html) or '<p><i>No SQLi/XSS reflection candidates found by the basic probes.</i></p>'}

  <h2>Screenshots</h2>
  {''.join(screenshots_html) or '<p><i>No screenshots captured.</i></p>'}
</body>
</html>"""


def generate_report(target: str, services: list, enum_results: dict, findings: list,
                     outdir: Path, formats: list) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {}

    markdown_content = build_markdown(target, services, enum_results, findings)

    if "md" in formats:
        md_path = outdir / "report.md"
        md_path.write_text(markdown_content)
        paths["md"] = str(md_path)

    if "txt" in formats:
        txt_path = outdir / "report.txt"
        txt_path.write_text(build_plain_text(target, services, enum_results, findings))
        paths["txt"] = str(txt_path)

    # Dedicated CVE-findings file — always generated alongside whatever
    # report formats were requested, since it's a distinct, focused artifact
    # (service -> CVE -> description/CVSS/severity) rather than a report format choice.
    cve_path = outdir / "cve_findings.txt"
    cve_path.write_text(build_cve_findings_file(target, findings))
    paths["cve_findings"] = str(cve_path)

    if "json" in formats:
        json_path = outdir / "report.json"
        json_path.write_text(json.dumps({
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "services": services,
            "enum_results": enum_results,
            "findings": findings,
        }, indent=2, default=str))
        paths["json"] = str(json_path)

    if "html" in formats:
        html_path = outdir / "report.html"
        html_path.write_text(build_html(target, services, enum_results, findings))
        paths["html"] = str(html_path)

    if "pdf" in formats:
        pdf_path = outdir / "report.pdf"
        try:
            from md2pdf.core import md2pdf
            md2pdf(str(pdf_path), md_content=markdown_content)
            paths["pdf"] = str(pdf_path)
        except ImportError:
            log.warning("md2pdf not installed (pip install md2pdf). Skipping PDF export; other formats still generated.")

    return paths