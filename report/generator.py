"""
report/generator.py
Builds the findings into Markdown, JSON, and (optionally) PDF reports.
"""

import json
from pathlib import Path
from datetime import datetime
from utils.logger import get_logger

log = get_logger("report")


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


def generate_report(target: str, services: list, enum_results: dict, findings: list,
                     outdir: Path, formats: list) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    paths = {}

    markdown_content = build_markdown(target, services, enum_results, findings)

    if "md" in formats:
        md_path = outdir / "report.md"
        md_path.write_text(markdown_content)
        paths["md"] = str(md_path)

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

    if "pdf" in formats:
        pdf_path = outdir / "report.pdf"
        try:
            from md2pdf.core import md2pdf
            md2pdf(str(pdf_path), md_content=markdown_content)
            paths["pdf"] = str(pdf_path)
        except ImportError:
            log.warning("md2pdf not installed (pip install md2pdf). Skipping PDF export; Markdown/JSON still generated.")

    return paths
