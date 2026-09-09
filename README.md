<div align="center">

# 🎯 ReconToReport

### Automated Recon-to-Report Pentesting Pipeline

**One command. Full recon, service enumeration, real CVE correlation, and a client-ready report.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](#license)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)]()
[![Made for](https://img.shields.io/badge/Made%20for-CTFs%20%26%20VAPT-red?style=flat-square)]()

*Stop chaining nmap → gobuster → searchsploit → manual-CVE-lookup → Word doc by hand.*
*Point ReconToReport at a target and get all of it, correlated and reported, automatically.*

</div>

---

## 📌 Why This Exists

Most recon tools stop at "here's what's open." **ReconToReport goes further** — it tells you what's actually *exploitable*, how severe it is according to real CVSS data, and hands you a report you can drop straight into a client deliverable or a CTF writeup.

| | AutoRecon | FinalRecon | **ReconToReport** |
|---|:---:|:---:|:---:|
| Network + service enum | ✅ | ⚠️ (web-only) | ✅ |
| Real CVE + CVSS correlation (NVD) | ❌ | ❌ | ✅ |
| Risk-scored findings | ❌ | ❌ | ✅ |
| Basic OWASP (SQLi/XSS) probing | ❌ | ❌ | ✅ |
| Auto-generated PDF/MD/JSON report | ❌ | ❌ | ✅ |
| Resume interrupted scans | ❌ | ❌ | ✅ |

---

## ⚡ Features

<table>
<tr>
<td width="50%">

**🔍 Recon & Enumeration**
- Nmap-powered scan (`quick` / `full` profiles)
- Auto-dispatches per detected service:
  - `HTTP/S` → gobuster + whatweb + OWASP probes
  - `SMB` → enum4linux-ng
  - `FTP` → anonymous login check
  - `SSH` → banner + ssh-audit
  - Domains → DNS records + zone-transfer check

</td>
<td width="50%">

**🛡️ Vulnerability Intelligence**
- Live **NVD API** lookup — real CVEs, real CVSS scores
- searchsploit cross-reference for public PoCs
- Severity ranked strictly by CVSS (no guessing)
- Findings sorted worst-first automatically

</td>
</tr>
<tr>
<td width="50%">

**📊 Reporting**
- Markdown, JSON, and PDF export
- Screenshot capture of live web services
- Clean, client-shareable output

</td>
<td width="50%">

**⚙️ Built for Real Workflows**
- Multi-target (`IP`, `CIDR`, or `targets.txt`)
- Resume/checkpoint on interrupted scans
- Slack/Discord webhook on completion
- Custom wordlist support

</td>
</tr>
</table>

---

## 🚀 Quick Start

```bash
git clone https://github.com/Raj7l69/ReconToReport.git
cd ReconToReport
pip3 install -r requirements.txt --break-system-packages
```

<details>
<summary><b>📦 External tools (click to expand)</b></summary>

```bash
sudo apt install nmap gobuster whatweb smbclient exploitdb dnsutils -y

# enum4linux-ng
git clone https://github.com/cddmp/enum4linux-ng.git

# ssh-audit
pip3 install ssh-audit --break-system-packages

# gowitness (optional — needed only for --screenshot)
go install github.com/sensepost/gowitness@latest
```

**NVD API key (recommended):** without one, CVE lookups are rate-limited to 5 req/30s. Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) and pass it with `--nvd-api-key`.

</details>

### Run it

```bash
# Basic scan
python3 main.py --target 10.10.10.5

# Full aggressive scan, screenshots, all export formats
python3 main.py --target 10.10.10.5 --profile full --screenshot --export pdf md json

# Multiple targets
python3 main.py --target-file targets.txt

# Resume an interrupted scan
python3 main.py --target 10.10.10.5 --resume

# Get pinged on Slack/Discord when it's done
python3 main.py --target 10.10.10.5 --webhook https://hooks.slack.com/services/XXX
```

<details>
<summary><b>⚙️ Full options reference</b></summary>

| Flag | Description |
|------|-------------|
| `--target` | Single IP, CIDR, or domain |
| `--target-file` | File with one target per line |
| `--profile` | `quick` (default) or `full` |
| `--wordlist` | Directory brute-force wordlist (swap in [SecLists](https://github.com/danielmiessler/SecLists) for real engagements) |
| `--export` | Any of `md`, `json`, `pdf` |
| `--screenshot` | Capture screenshots of discovered web services |
| `--resume` | Resume from last checkpoint |
| `--webhook` | Slack/Discord webhook URL |
| `--nvd-api-key` | Raise the NVD CVE-lookup rate limit |

</details>

---

## 🗂️ Project Structure

```
ReconToReport/
├── core/            → nmap scanning, service parsing, enum dispatch
├── modules/          → web / SMB / FTP / SSH / DNS enumeration
├── vuln/             → NVD CVE + CVSS correlation, searchsploit matching
├── report/           → Markdown / JSON / PDF report builder
├── utils/            → checkpoint (resume), webhook notifier, logger
├── wordlists/        → sample wordlist (swap for SecLists in real use)
└── main.py           → orchestrator
```

---

## 🧭 Roadmap

- [ ] Subdomain enumeration (subfinder/amass integration)
- [ ] Expand OWASP probes beyond SQLi/XSS reflection
- [ ] Local caching of NVD responses across runs

---

## ⚠️ Disclaimer

Built for **authorized security testing only** — CTFs, labs, and engagements you have explicit written permission for. Do not run this against systems you don't own or aren't authorized to test.

---

<div align="center">

Built by **Rajendra Singh** ([@Raj7l69](https://github.com/Raj7l69)) — B.Tech CSE (Cyber Security), Quantum University

*If this helped your workflow, a ⭐ on the repo is appreciated.*

</div>
