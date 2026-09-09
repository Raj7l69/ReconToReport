<div align="center">

# 🎯 ReconToReport

### An Automated Offensive Security Pipeline — Recon, Vulnerability Intelligence & Reporting in One Run

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![NVD](https://img.shields.io/badge/CVE%20Data-Live%20NVD%20API-red?style=for-the-badge&logo=hackthebox&logoColor=white)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)]()

</div>

<br>

<p align="center">
<i>A pentest engagement starts the same way every time — scan, enumerate, look up CVEs, screenshot evidence, write it all up. That whole chain, run by hand, eats hours before the actual assessment even begins.</i><br><br>
<b>ReconToReport collapses that chain into one command</b> — target in, evidence-backed report out.
</p>

<br>

---

## 🧠 The Idea Behind It

Reconnaissance tooling generally does one of two things well: either it's a **fast scanner** that tells you what's open, or it's a **deep enumerator** that digs into individual services. What's usually missing is the layer that actually matters to a pentester under time pressure — **turning raw scan output into ranked, evidence-backed findings** without touching ten separate tools by hand.

ReconToReport was built to close that gap: one pipeline that scans, enumerates by service type, cross-references *live* CVE data, scores risk by real CVSS numbers, and writes the report — so the engineering effort goes into interpreting findings, not assembling them.

<br>

## 🔬 How the Pipeline Works

```
   🎯                🔍                  🧭                    🛡️                   📄
 TARGET   ──────▶   NMAP SCAN   ──────▶  SERVICE-AWARE   ──────▶  NVD CVE       ──────▶  REPORT
 (IP/Domain)        (quick/full)         ENUMERATION            CORRELATION            (MD/JSON/PDF)
                                          per service type       + CVSS scoring
```

| Stage | What Happens |
|---|---|
| **1️⃣ Discovery** | Nmap identifies live hosts, open ports, and running services with version fingerprinting. Two speed profiles — `quick` for a fast top-port sweep, `full` for an exhaustive all-port pass with OS detection. |
| **2️⃣ Service-Aware Enumeration** | Each detected service triggers its own specialist module instead of a one-size-fits-all scan — HTTP gets directory brute-forcing and tech fingerprinting, SMB gets share/user enumeration, SSH gets a configuration audit, and domain targets get DNS record and zone-transfer checks. |
| **3️⃣ Vulnerability Correlation** | Every service/version pair is queried live against the **NVD database** — real CVE IDs, real descriptions, real CVSS base scores. A parallel searchsploit check flags anything with a known public exploit. |
| **4️⃣ Risk Scoring** | Findings are ranked Critical → High → Medium → Low, driven strictly by the actual CVSS score returned — not a keyword heuristic guessing at severity. |
| **5️⃣ Web Probing** | Discovered web endpoints get lightweight OWASP-style checks — error-based SQLi signatures and reflected-XSS detection — flagging candidates worth a closer manual look. |
| **6️⃣ Reporting** | Every finding, screenshot, and enumeration artifact is compiled into a structured report — Markdown for quick review, JSON for programmatic use, PDF for handing off. |

<br>

## ⚡ Full Feature List

**Core Pipeline**

1. 🔍 **Nmap scanning** — fast and full profiles, with service/version detection
2. 🧭 **Service-based auto enumeration** — HTTP, SMB, FTP, SSH, and DNS each handled by a dedicated module
3. 🛡️ **CVE correlation** — live NVD database lookup + searchsploit cross-check
4. 🕷️ **Web probing** — directory brute-forcing plus basic OWASP-style SQLi/XSS checks
5. 📄 **Automated report generation** — every finding compiled into a structured, shareable report

**Enhancements**

6. 🎯 **Multi-target support** — single IP, IP range, or a `targets.txt` list
7. 📸 **Automatic screenshot capture** — visual evidence of discovered web services
8. 📊 **Risk scoring** — CVSS-based Critical / High / Medium / Low severity ranking
9. ⏸️ **Resume / checkpoint** — interrupted scans continue instead of restarting
10. ⚙️ **Scan profiles** — `--quick` for speed, `--full` for depth
11. 📚 **Custom wordlist support** — bring your own brute-force lists
12. 🗂️ **Multi-format export** — PDF, JSON, and Markdown reports
13. 🔔 **Webhook notifications** — Slack/Discord alert when a scan completes

<br>

## 🧭 Service-Specific Enumeration

<table>
<tr><td width="15%" align="center"><b>🌐 HTTP/S</b></td><td>Directory brute-forcing (gobuster), technology fingerprinting (whatweb), lightweight SQLi/XSS reflection probing</td></tr>
<tr><td align="center"><b>🗂️ SMB</b></td><td>Share and user enumeration via enum4linux-ng</td></tr>
<tr><td align="center"><b>📁 FTP</b></td><td>Anonymous login testing and banner grabbing</td></tr>
<tr><td align="center"><b>🔑 SSH</b></td><td>Banner capture plus algorithm/configuration audit via ssh-audit</td></tr>
<tr><td align="center"><b>🌍 DNS</b></td><td>Full record enumeration (A/AAAA/MX/NS/TXT/SOA/CNAME) and zone-transfer (AXFR) misconfiguration testing</td></tr>
</table>

<br>

## 🏗️ Engineering Notes

- **Modular dispatch architecture** — the enumeration layer routes purely on detected service name, so adding a new service handler means dropping in one new module, not touching the core pipeline.
- **Real-time CVE correlation, not a static ruleset** — every scan queries NVD live, so findings reflect the current vulnerability database rather than a bundled snapshot that goes stale.
- **State-aware execution** — scan progress is checkpointed per target, so a long multi-host run surviving a network drop or a `Ctrl+C` doesn't mean starting over.
- **Structured output by design** — every module returns typed dict/JSON output rather than raw text, which is what makes automated report generation possible instead of manual copy-pasting.

<br>

## 🛠️ Built With

`Python 3` · `Nmap` · `Gobuster` · `WhatWeb` · `enum4linux-ng` · `ssh-audit` · `dig` · `NVD REST API` · `searchsploit` · `gowitness`

<br>

## 🗂️ Structure

```
ReconToReport/
├── 🔎 core/         nmap scanning, service parsing, enumeration dispatch
├── 🧭 modules/       web / SMB / FTP / SSH / DNS enumeration handlers
├── 🛡️ vuln/          NVD CVE + CVSS correlation, searchsploit matching
├── 📄 report/        Markdown / JSON / PDF report builder
├── ⚙️ utils/          checkpoint/resume, webhook notifier, logger
├── 📚 wordlists/     directory brute-force wordlists
└── 🎯 main.py         pipeline orchestrator
```

<br>

## ⚠️ Disclaimer

Built strictly for **authorized security testing** — CTFs, personal labs, and engagements with explicit written permission. Not intended for use against systems you don't own or aren't authorized to assess.

<br>

---

<div align="center">

### 👨‍💻 Rajendra Singh

[![GitHub](https://img.shields.io/badge/GitHub-Raj7l69-181717?style=for-the-badge&logo=github)](https://github.com/Raj7l69)

⭐ **If this tool is useful, consider starring the repo.**

</div>
