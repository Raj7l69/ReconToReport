# 🛠️ Installation & Usage

## Requirements

- Python 3.10+
- Linux (Kali/Parrot recommended — most enum tools assume a pentest distro)

## 1. Clone & Install Python Dependencies

```bash
git clone https://github.com/Raj7l69/ReconToReport.git
cd ReconToReport
pip3 install -r requirements.txt --break-system-packages
```

## 2. Install External Tools

ReconToReport orchestrates existing, well-known security tools rather than reinventing them.

```bash
sudo apt install nmap gobuster whatweb smbclient exploitdb dnsutils -y

# enum4linux-ng (not always in apt — clone directly)
git clone https://github.com/cddmp/enum4linux-ng.git

# ssh-audit (SSH config/algorithm checks)
pip3 install ssh-audit --break-system-packages

# gowitness (optional — only needed for --screenshot)
go install github.com/sensepost/gowitness@latest
```

## 3. (Recommended) Get a Free NVD API Key

CVE correlation queries the NVD REST API. Without a key it's rate-limited to 5 requests/30s, which makes scans with many services slow. A free key raises that to ~50 requests/30s.

Request one at: https://nvd.nist.gov/developers/request-an-api-key

## 4. Run It

```bash
# Basic scan — quick profile, Markdown + JSON report
python3 main.py --target 10.10.10.5

# Full aggressive scan with screenshots and PDF report
python3 main.py --target 10.10.10.5 --profile full --screenshot --export pdf md json

# Multiple targets from a file
python3 main.py --target-file targets.txt

# Resume an interrupted scan
python3 main.py --target 10.10.10.5 --resume

# Faster CVE correlation with an NVD API key
python3 main.py --target 10.10.10.5 --nvd-api-key YOUR_KEY_HERE

# Get a Slack/Discord ping when it's done
python3 main.py --target 10.10.10.5 --webhook https://hooks.slack.com/services/XXX
```

## All Options

| Flag | Description |
|------|-------------|
| `--target` | Single IP, CIDR, or domain |
| `--target-file` | File with one target per line |
| `--profile` | `quick` (default) or `full` |
| `--wordlist` | Directory brute-force wordlist (default: `wordlists/common.txt` — swap in [SecLists](https://github.com/danielmiessler/SecLists) for real engagements) |
| `--export` | One or more of `md`, `json`, `pdf` |
| `--screenshot` | Capture screenshots of discovered web services |
| `--resume` | Resume from last checkpoint |
| `--webhook` | Slack/Discord webhook URL for completion alert |
| `--nvd-api-key` | Optional NVD API key to raise the CVE-lookup rate limit |

## Output

Results are written to `output/<target>/`:
- `report.md` / `report.json` / `report.pdf` — the final findings report
- `nmap_scan.xml` — raw nmap output
- `gobuster_*.txt`, `whatweb_*.txt`, `smb_enum.txt`, `dns_enum.txt` — raw tool output per module
- `screenshots/` — captured web service screenshots (if `--screenshot` used)
- `.checkpoint.json` — scan progress state (used by `--resume`)

## Disclaimer

For authorized security testing and educational use only (CTFs, labs, engagements you have written permission for). Do not run this against systems you don't own or don't have explicit permission to test.
