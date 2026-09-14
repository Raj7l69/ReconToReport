# 🛠️ Installation & Usage

## Requirements

- Python 3.10+
- Linux (Kali/Parrot recommended — most enum tools assume a pentest distro)

## 1. Clone & Install Python Dependencies

**Recommended: use a virtual environment**, so ReconToReport's Python packages never touch or conflict with Kali's system-managed packages:

```bash
git clone https://github.com/Raj7l69/ReconToReport.git
cd ReconToReport
python3 -m venv venv
source venv/bin/activate        # run this every time you open a new terminal for this project
pip3 install -r requirements.txt
```

While the venv is active, `python3 main.py` (or `rtr`, if installed per step 4) automatically uses these isolated packages — no `--break-system-packages` needed anywhere below. Deactivate anytime with `deactivate`.

<details>
<summary><b>Not using a venv?</b> (not recommended, but here's how)</summary>

`--break-system-packages` installs directly into Kali's system Python, bypassing the safety check that normally blocks this. It works, but it means these packages now live alongside every apt-managed Python package on your system — a version conflict with something else on your machine is possible, even if unlikely for these specific dependencies.

```bash
pip3 install -r requirements.txt --break-system-packages
```
If you go this route, apply the same flag to every `pip3 install` command in this guide.

</details>

<details>
<summary><b>Tired of typing <code>source venv/bin/activate</code> every time?</b> Use direnv to auto-activate on <code>cd</code></summary>

```bash
sudo apt install direnv -y
echo 'eval "$(direnv hook zsh)"' >> ~/.zshrc   # Kali's default shell is zsh
source ~/.zshrc

# inside the project folder:
echo "source venv/bin/activate" > .envrc
direnv allow
```

Now the venv activates automatically every time you `cd` into the project folder, and deactivates when you leave it. `.envrc` is local to your machine and already excluded via `.gitignore`.

</details>

## 2. Install External Tools

ReconToReport orchestrates existing, well-known security tools rather than reinventing them. `apt`-installed tools (nmap, gobuster, etc.) are always available system-wide; `pip`-installed ones (ssh-audit) are only on PATH while your venv is active — which is fine, since you'll have it active whenever you run the tool anyway.

```bash
sudo apt install nmap gobuster whatweb smbclient exploitdb dnsutils -y

# enum4linux-ng (not always in apt — clone directly)
git clone https://github.com/cddmp/enum4linux-ng.git

# ssh-audit (SSH config/algorithm checks)
pip3 install ssh-audit

# gowitness (optional — only needed for --screenshot)
go install github.com/sensepost/gowitness@latest

# SecLists (strongly recommended — gobuster wordlist prompts pull from here)
sudo apt install seclists -y
# or: git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

## 3. Set Up API Keys (all optional, all free)

ReconToReport pulls vulnerability data from four sources. Here's what each one actually is, in plain terms:

- **NVD** (National Vulnerability Database) — the official US government database of CVEs and their CVSS severity scores. This is where the core "what's the severity" number comes from.
- **Vulners** — a search engine that aggregates 200+ sources (Exploit-DB, Metasploit, GitHub PoCs, advisories) so you can find exploit code/links for a CVE in one lookup instead of searching each source separately.
- **EPSS** (Exploit Prediction Scoring System) — a free, public score (0-100%) estimating the real-world probability a CVE will actually be exploited in the next 30 days. CVSS tells you how bad a bug *could* be; EPSS tells you how likely it is to actually be used.
- **CISA KEV** (Known Exploited Vulnerabilities catalog) — a public list, maintained by the US Cybersecurity and Infrastructure Security Agency, of CVEs with *confirmed* active exploitation in the wild. If a CVE is on this list, it isn't theoretical — attackers are using it right now.

Copy the template and fill in whichever keys you have:
```bash
cp .env.example .env
```

| Key | Where to get it | What it does without a key |
|-----|------------------|------------------------------|
| `NVD_API_KEY` | https://nvd.nist.gov/developers/request-an-api-key | Still works — rate-limited to 5 req/30s instead of ~50 req/30s |
| `VULNERS_API_KEY` | https://vulners.com (free account → API KEYS tab → generate with scope `api`) | Exploit-link enrichment from Vulners is skipped; NVD + searchsploit still run |

EPSS and CISA KEV need **no key at all** — both are free, public, unauthenticated APIs and run automatically.

`.env` is already in `.gitignore` — it will never be committed. `main.py` loads it automatically via `python-dotenv` (included in `requirements.txt`).

## 4. (Optional) Install as a System Command

By default the tool runs as `python3 main.py`. If you'd rather run it as a
standalone command from anywhere — like `msfconsole` or `autorecon` — install
it in editable mode:

```bash
pip3 install -e .
```

This registers an `rtr` command. Every example in the next section works
identically with `python3 main.py` or `rtr` — use whichever you prefer.

<details>
<summary><b>Want shell tab-completion?</b> (e.g. <code>rtr --tar</code> + Tab → <code>--target</code>)</summary>

```bash
pip3 install argcomplete          # already included if you ran requirements.txt / pip install -e .
eval "$(register-python-argcomplete rtr)"
```

Add that `eval` line to `~/.zshrc` to make it permanent:
```bash
echo 'eval "$(register-python-argcomplete rtr)"' >> ~/.zshrc
source ~/.zshrc
```

</details>

## 5. Run It

```bash
# Basic scan — interactive prompts for port selection, gobuster modes, etc.
python3 main.py --target 10.10.10.5
# ...or, if you installed it as a command:
rtr --target 10.10.10.5

# Full profile, screenshots, all report formats
python3 main.py --target 10.10.10.5 --profile full --screenshot --export pdf md json html txt

# Multiple targets from a file (prompts once to "apply to all" or per-target)
python3 main.py --target-file targets.txt

# Resume an interrupted scan
python3 main.py --target 10.10.10.5 --resume

# Fully unattended (no prompts, sane defaults, targets run in parallel)
python3 main.py --target-file targets.txt --no-prompt --workers 5

# Skip interactive nmap prompts with your own flags
python3 main.py --target 10.10.10.5 --nmap-args "-Pn -sV --top-ports 1000"

# Get a Slack/Discord ping when it's done
python3 main.py --target 10.10.10.5 --webhook https://hooks.slack.com/services/XXX
```

> **Root-required scans (`-sS`, `-sU`):** you don't need to run the whole tool with `sudo`. If you select a SYN or UDP scan in the interactive menu and you're not root, ReconToReport automatically re-runs just that nmap command with `sudo` and prompts you for your password at that point.

## What Gets Asked, Interactively

Unless you pass `--nmap-args` or `--no-prompt`, a normal run walks you through:

1. **Port selection** — top 100, top 1000 (default), specific ports, a range, or all ports
2. **Scan type & extras** — SYN/Connect/ACK/Window/Null/FIN/Xmas, `-Pn`, UDP, NSE script categories (vuln/safe/auth/discovery/exploit/default) or a specific script name, `-A`, min-rate, fragmentation — or skip all of this and type a fully custom nmap command instead
3. **Timing template** — T0 (paranoid) through T5 (insane), defaults to T4
4. **Per web service found:** gobuster dir/dns/vhost — run or skip each independently, pick a wordlist (bundled default, a listed SecLists path, or your own), plus extensions/thread count/TLS-skip and WhatWeb's aggression level
5. **If multiple targets:** whether to reuse the same answers for all of them, or be asked per-target

None of this applies with `--no-prompt` (sane defaults, no questions) or `--nmap-args "..."` (skips only the nmap menu).

## All Options

| Flag | Description |
|------|-------------|
| `--target` | Single IP, CIDR, or domain |
| `--target-file` | File with one target per line |
| `--profile` | `quick` (default) or `full` |
| `--wordlist` | Fallback wordlist if no SecLists path is chosen interactively |
| `--export` | Any of `md`, `txt`, `json`, `html`, `pdf` (default: `md json txt`) |
| `--screenshot` | Capture screenshots of discovered web services |
| `--resume` | Resume from last checkpoint |
| `--webhook` | Slack/Discord webhook URL for completion alert |
| `--nvd-api-key` | NVD API key (or set `NVD_API_KEY` in `.env`) |
| `--vulners-api-key` | Vulners API key (or set `VULNERS_API_KEY` in `.env`) |
| `--nmap-args` | Raw nmap flags, e.g. `'-Pn -sS --script vuln'` — skips all interactive nmap prompts |
| `--no-prompt` | Skip all interactive prompts (nmap options, gobuster mode/wordlist, apply-to-all) — sane defaults, needed for unattended/parallel runs |
| `--workers` | Max targets scanned concurrently in non-interactive mode (default: 3) |
| `--verbose` / `-v` | Show DEBUG-level output on the console |
| `--quiet` / `-q` | Only show WARNING/ERROR on the console |
| `--log-file` | Write full debug logs here (default: `<output-dir>/reconToReport.log`) |

## Output

Results are written to `output/<target>/`:
- `report.md` / `report.txt` / `report.json` / `report.html` / `report.pdf` — whichever formats were requested
- `cve_findings.txt` — **always generated**: per-service CVE ID, description, CVSS, EPSS score, CISA KEV status, and exploit links
- `nmap_scan.xml` — machine-readable scan output (used internally)
- `nmap_scan.txt` — plain, human-readable nmap output
- `gobuster_<mode>_*.txt`, `whatweb_*.txt`, `smb_enum.txt`, `dns_enum.txt`, `ssh_audit_*.txt`, `ftp_enum_*.txt` — raw tool output per module
- `screenshots/` — captured web service screenshots (if `--screenshot` used)
- `.checkpoint.json` — scan progress state (used by `--resume`)
- `reconToReport.log` — full debug-level log for the run

## Running the Test Suite

```bash
pip3 install pytest
pytest tests/ -v
```

For a full manual QA pass covering every flag and interactive option, see `TESTING_CHECKLIST.md`.

## Disclaimer

For authorized security testing and educational use only (CTFs, labs, engagements you have written permission for). Do not run this against systems you don't own or don't have explicit permission to test.