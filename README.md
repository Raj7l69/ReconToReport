<div align="center">

<br>

# 🎯 ReconToReport

<h3>Point it at a target. Walk away. Come back to a ranked, evidence-backed vulnerability report.</h3>

<br>

![Python](https://img.shields.io/badge/PYTHON-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white&labelColor=1a1a2e)
![NVD](https://img.shields.io/badge/CVE%20INTEL-LIVE%20NVD-e63946?style=for-the-badge&logo=hackthebox&logoColor=white&labelColor=1a1a2e)
![EPSS](https://img.shields.io/badge/RISK-EPSS%20%2B%20CISA%20KEV-f77f00?style=for-the-badge&logo=shieldsdotio&logoColor=white&labelColor=1a1a2e)
![Tests](https://img.shields.io/badge/TESTS-22%20PASSING-06d6a0?style=for-the-badge&logo=pytest&logoColor=white&labelColor=1a1a2e)
![License](https://img.shields.io/badge/LICENSE-MIT-118ab2?style=for-the-badge&labelColor=1a1a2e)

<br>

**[📥 Installation & Usage Guide →](INSTALL.md)**

<br>

</div>

> *Every pentest engagement starts the same tedious way: scan → enumerate → Google every CVE by hand → screenshot evidence → write it all up in Word. Hours gone before the real work even starts.*
>
> **ReconToReport kills that grind.** One command runs the whole chain — and instead of dumping raw CVSS numbers on you, it tells you which vulnerability an attacker is **actually exploiting right now.**

<div align="center">

**No more guessing which CVE actually matters.**
**No more ten tabs open just to build one report.**
**No more finding out three services deep that your wordlist was garbage.**

</div>

<br>

<div align="center">

### 📊 By The Numbers

| 5 | 4 | 5 | 18+ | 22 |
|:---:|:---:|:---:|:---:|:---:|
| enumeration modules<br>(HTTP·SMB·FTP·SSH·DNS) | vulnerability<br>intel sources | report<br>formats | interactive scan &<br>enum options | passing<br>tests |

</div>

<br>

---

<br>

## 🧬 Why This Isn't "Just Another Recon Script"

Most tools stop at CVSS. **CVSS tells you how bad a vulnerability *could* be — not whether anyone is actually using it.**

ReconToReport pulls in the two signals that actually matter for prioritization, on top of raw CVSS:

<div align="center">

| 🧮 CVSS | 📈 EPSS | 🚨 CISA KEV |
|:---:|:---:|:---:|
| *"How severe is this?"* | *"What's the probability this gets exploited in the next 30 days?"* | *"Is this being actively weaponized right now, confirmed by the US government?"* |
| Theoretical severity | Real-world prediction | Real-world confirmation |

</div>

A 7.5-severity CVE that's on the CISA KEV list is a **fix-today** problem. A 9.8-severity CVE nobody has ever exploited might not be. Most tools can't tell you the difference. **This one does.**

<br>

## 🖥️ What You Actually See

```
$ rtr --target 10.10.10.5

   ____                     _____    ____                       _
  |  _ \ ___  ___ ___  _ __|_   _|__|  _ \ ___ _ __   ___  _ __| |_
  | |_) / _ \/ __/ _ \| '_ \ | |/ _ \ |_) / _ \ '_ \ / _ \| '__| __|
  |  _ <  __/ (_| (_) | | | || | (_) |  _ <  __/ |_) | (_) | |  | |_
  |_| \_\___|\___\___/|_| |_||_|\___/|_| \_\___| .__/ \___/|_|   \__|
        Automated Recon -> Enumeration -> CVE Correlation -> Report
                              by Ra_one

[INFO] Stage 4: Correlating services against NVD CVE database
[INFO] Loaded CISA KEV catalog: 1,709 known-exploited CVEs

  [Critical] CVSS 9.8  EPSS 96%  Port 21   ftp   vsftpd 2.3.4
  [Critical] CVSS 10.0 EPSS 3%   Port 5900 vnc   VNC
  [Critical] CVSS 9.8  EPSS 18%  Port 23   telnet ...  [KEV: ACTIVELY EXPLOITED]

[INFO] Done. Reports: report.md, report.txt, report.html, cve_findings.txt
```

<br>

## ⚙️ The Pipeline

```
   🎯            🔎            🧭                🛡️                  📄
 TARGET  ──▶  NMAP SCAN  ──▶  SERVICE-AWARE  ──▶  VULNERABILITY  ──▶  EVIDENCE-BACKED
(IP/Domain)  (quick/full)    ENUMERATION         INTELLIGENCE        REPORT
                              per service type    NVD·Vulners·        (MD·TXT·JSON·
                                                   EPSS·CISA KEV       HTML·PDF)
```

<table>
<tr><td width="4%">🔍</td><td width="16%"><b>Discovery</b></td><td>Interactive port/scan-type selection — top 100/1000, custom ranges, SYN/Connect/ACK/Null/FIN/Xmas, timing templates, NSE scripts, or a fully custom nmap command. Root-only scans auto-elevate via <code>sudo</code> for just that one call.</td></tr>
<tr><td>🧭</td><td><b>Enumeration</b></td><td>Every open service triggers its own specialist — HTTP gets gobuster across <b>all three modes</b> (dir/dns/vhost) with real SecLists wordlists, extension fuzzing, thread tuning, TLS-skip for self-signed certs, tech fingerprinting, and OWASP probes. SMB, FTP, SSH, and DNS each get their own handler.</td></tr>
<tr><td>🛡️</td><td><b>Correlation</b></td><td>Live NVD lookup for real CVEs and CVSS scores, cross-checked against <b>searchsploit</b> and <b>Vulners</b> (200+ aggregated sources) for exploit availability.</td></tr>
<tr><td>📈</td><td><b>Risk Enrichment</b></td><td>The top CVE per service gets an <b>EPSS</b> exploitation-probability score and a <b>CISA KEV</b> active-exploitation check — so ranking reflects real-world risk, not just a CVSS number.</td></tr>
<tr><td>📄</td><td><b>Reporting</b></td><td>Everything compiled into Markdown, plain text, JSON, HTML, and PDF — plus a dedicated <code>cve_findings.txt</code> with every CVE's description, CVSS, EPSS, KEV status, and exploit links.</td></tr>
</table>

<br>

## ⚡ Everything It Does

<table>
<tr><td valign="top" width="50%">

**🎯 Core Pipeline**
- 🔍 Interactive nmap scanning — ports, scan types, timing, full custom commands
- 🧭 Service-based auto enumeration (HTTP · SMB · FTP · SSH · DNS)
- 🛡️ Multi-source CVE correlation — NVD + searchsploit + Vulners
- 📈 Real-world risk enrichment — EPSS + CISA KEV
- 🕷️ Gobuster (dir/dns/vhost) — SecLists wordlists, extension fuzzing, TLS-skip
- 📄 Five report formats, generated automatically

</td><td valign="top" width="50%">

**🚀 Built to Actually Be Used**
- 🎯 Multi-target — single IP, range, or file, scanned in parallel
- 📸 Automatic screenshot evidence capture
- ⏸️ Resume/checkpoint on interrupted scans
- 🔒 Input validation before every subprocess call
- ⚡ Rate-limited, cached, concurrent NVD lookups
- 🧪 Full pytest test suite — 22 passing
- 🔑 Secrets live in `.env`, never in source

</td></tr>
</table>

<br>

## 🧭 Service-Specific Enumeration

<table>
<tr><td width="14%" align="center">🌐<br><b>HTTP/S</b></td><td>Gobuster across dir/dns/vhost (each run or skipped independently) with real SecLists wordlists, extension fuzzing, custom thread counts, TLS-verification skip for self-signed certs, whatweb tech fingerprinting, OWASP SQLi/XSS reflection probing</td></tr>
<tr><td align="center">🗂️<br><b>SMB</b></td><td>Share and user enumeration via enum4linux-ng</td></tr>
<tr><td align="center">📁<br><b>FTP</b></td><td>Anonymous login testing and banner grabbing</td></tr>
<tr><td align="center">🔑<br><b>SSH</b></td><td>Banner capture plus algorithm/configuration audit via ssh-audit</td></tr>
<tr><td align="center">🌍<br><b>DNS</b></td><td>Full record enumeration and zone-transfer (AXFR) misconfiguration testing</td></tr>
</table>

<br>

## 🛡️ The Vulnerability Intelligence Stack

<table>
<tr><td width="18%" align="center">🗄️<br><b>NVD</b></td><td>Authoritative CVE list and official CVSS base scores — the foundation for everything else</td></tr>
<tr><td align="center">🕳️<br><b>Searchsploit</b></td><td>Exploit-DB cross-check for known public exploit PoCs</td></tr>
<tr><td align="center">🌐<br><b>Vulners</b></td><td>200+ aggregated sources — Exploit-DB, Metasploit, GitHub PoCs, vendor advisories — broader coverage than any single source</td></tr>
<tr><td align="center">📈<br><b>EPSS</b></td><td>0-100% real-world probability of exploitation in the next 30 days</td></tr>
<tr><td align="center">🚨<br><b>CISA KEV</b></td><td>The US government's official list of CVEs with <i>confirmed</i> active exploitation — the strongest "drop everything and patch this" signal that exists</td></tr>
</table>

<br>

## 🔬 The Design Choices That Actually Matter

- 🧩 **Modular dispatch** — the enumeration layer routes purely on detected service name; adding a new service means dropping in one module, not touching the core pipeline
- 🧮 **Layered risk scoring, not a single number** — CVSS + EPSS + CISA KEV combined, because CVSS alone is where most tools stop and where most bad prioritization decisions start
- ⚡ **Concurrent, rate-limited NVD queries** — a thread pool gated by a sliding-window limiter, so multiple services get checked in parallel without ever exceeding NVD's real rate limit
- 💾 **Local response caching** — a 7-day TTL cache means re-scanning the same lab or target skips redundant network calls entirely
- 🔒 **Validate before you execute** — every target is checked against strict IP/CIDR/domain rules before it ever touches a subprocess call
- 🔑 **Minimal privilege by default** — the tool runs as a normal user; only the one nmap call that actually needs root auto-elevates via `sudo`, nothing else
- 🧵 **Concurrent multi-target scanning** — non-interactive runs process multiple hosts in parallel via a worker pool
- 💽 **State-aware execution** — checkpointed per target, so a dropped connection or a `Ctrl+C` mid-scan doesn't mean starting from zero
- 🧪 **Tested, not just written** — parsing, validation, severity scoring, and rate-limiting logic are all covered by `pytest`

<br>

## 🛠️ Built With

`Python 3` · `Nmap` · `Gobuster` · `WhatWeb` · `enum4linux-ng` · `ssh-audit` · `dig` · `NVD REST API` · `Vulners API` · `EPSS API` · `CISA KEV Catalog` · `searchsploit` · `gowitness` · `pytest` · `argcomplete`

<br>

## 🗂️ Structure

```
ReconToReport/
├── 🔎 core/         nmap scanning, service parsing, enumeration dispatch
├── 🧭 modules/       web / SMB / FTP / SSH / DNS enumeration handlers
├── 🛡️ vuln/          NVD + Vulners + EPSS + CISA KEV correlation and enrichment
├── 📄 report/        Markdown / TXT / JSON / HTML / PDF report builder
├── ⚙️ utils/          checkpoint, rate limiter, cache, validator, webhook, logger
├── 🧪 tests/         pytest test suite
├── 📚 wordlists/     directory brute-force wordlists
└── 🎯 main.py         pipeline orchestrator
```

<br>

## 📥 Setup & Usage

Full installation steps, every CLI flag, API key setup, and output file reference live in **[INSTALL.md](INSTALL.md)**.

<br>

## ⚠️ Disclaimer

Built strictly for **authorized security testing** — CTFs, personal labs, and engagements with explicit written permission. Not intended for use against systems you don't own or aren't authorized to assess.

<br>

---

<div align="center">
<br>

### 🕶️ Rajendra Singh — Offensive Security

[![GitHub](https://img.shields.io/badge/GitHub-Raj7l69-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Raj7l69)

<br>

⭐ **If this saved you time on your next engagement, a star helps others find it.**

<br>
</div>