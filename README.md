# Homelab Cyber Range

This repository documents my personal cybersecurity lab built on Proxmox, OPNsense, Kali Linux, Ubuntu, and Windows 11.

## Goals

- Practice networking, firewalls, and VLAN segmentation
- Run offensive security tools safely in an isolated lab
- Build blue-team skills with logging, monitoring, and hardening

## Lab components

- Proxmox host running multiple VMs
- OPNsense firewall (bare metal and internal lab firewall)
- Kali Linux and Ubuntu servers for testing
- Windows 11 workstation for client-side labs

## What you will find here

- Network diagrams of the lab
- Notes and configurations (with secrets removed)
- Lab writeups explaining what I tested and what I learned
  
## Pentesting in the Lab

I use this environment to practice ethical hacking and blue-team defense:

- Kali Linux as an attack box
- Intentionally vulnerable targets (e.g., DVWA, Metasploitable, test web apps)
- OPNsense rules to keep the lab isolated from my home network
- Tools such as Nmap, Metasploit, Burp Suite, and Wireshark

All testing is performed only on systems I own or have explicit permission to test.

### External access through OPNsense

To simulate a more realistic attack path from my main PC, I configured OPNsense WAN rules and Destination NAT to expose selected lab services safely to the lab edge.

Current externally reachable lab services:

- `http://192.168.2.127:3000` — OWASP Juice Shop
- `http://192.168.2.127:8081` — DVWA
- `http://192.168.2.127:8082/WebGoat` — OWASP WebGoat

These exposures are temporary and used only for controlled lab testing and documentation.

## Vulnerability Scanning with OpenVAS

I run regular vulnerability scans against my homelab using Greenbone Community Edition (OpenVAS) on a dedicated VM.

### Scanner setup

- **Scanner VM:** `openvas-scanner` running Ubuntu Server on Proxmox
- **Targets:** Windows 11 workstation, Ubuntu server(s), and other lab services
- **Network:** Scanner is on the isolated lab VLAN, segmented by OPNsense

### Scan schedule

- **Frequency:** Weekly full scan of the lab subnet
- **Ad-hoc scans:** After major OS/application updates or lab changes

### What I track

- High/critical vulnerabilities found on each host
- Configuration issues (e.g., weak protocols, missing patches)
- Progress over time as I patch and harden systems

### Documentation

Scan summaries and remediation notes live in:

- `vuln-scans/` – Markdown files describing each scan, key findings, and what I fixed

### Lab roles

- **Kali Linux (`192.168.3.149`)** — attacker / scanner host. This VM runs the self-hosted GitHub Actions runner and executes Nmap (and Nessus API calls) against the targets. It is intentionally **not** listed in `target.txt`.
- **Ubuntu Server (`192.168.3.60`)** — scan target.
- **Windows 11 (`192.168.3.174`)** — scan target (current primary target).

### Files

- `target.txt` — expected **host/IP** VM inventory for Nmap scans. Add your current VM IPs, hostnames, or CIDRs here. Do **not** put web app URLs here.
- `web-targets.txt` — **web application** inventory (labelled `LABEL = URL` lines) scanned with lightweight web tooling. See [Host targets vs web targets](#host-targets-vs-web-targets).
- `scripts/homelab_vuln_scan.sh` — scanner script (Nmap + optional Nessus API + optional web checks).
- `.github/workflows/homelab-vulnerability-scan.yml` — weekday GitHub Action (Mon–Fri, 11:00 UTC).
- `scan-state/baseline.json` — saved open-port baseline used for net-new comparisons.
- `reports/latest-vulnerability-report.md` — latest human-readable report (generated).
- `reports/latest-findings.json` — latest machine-readable findings (generated).

### What it tracks

- Expected hosts that appear for the first time compared with the saved baseline.
- Unrecognized live hosts discovered in configured discovery CIDRs but not listed in `target.txt`.
- Net-new open ports since the previous baseline.
- Ports that disappeared since the previous baseline.
- Nessus vulnerability summary findings when Nessus API settings are configured.

### Host targets vs web targets

The scanner separates two kinds of targets so each gets the right tooling:

- **Host targets (`target.txt`)** — IPs, hostnames, or CIDRs scanned with **Nmap** (`-sV`, optional `-O`). This drives host discovery, open-port baselining, and net-new port/host detection.
- **Web targets (`web-targets.txt`)** — full application **URLs** scanned with lightweight, safe/default web tooling. Each line is `LABEL = URL`, for example:

  ```text
  Juice Shop = http://192.168.3.53:3000
  WebGoat    = http://192.168.2.53:8082/WebGoat/login
  DVWA       = http://192.168.3.53:8081/login.php
  Proxmox    = http://192.168.2.53:8006
  ```

Keep URLs out of `target.txt` and IPs/CIDRs out of `web-targets.txt`. If `web-targets.txt` is absent (or `WEB_TARGET_FILE` points nowhere), web checks are skipped and the host scan is unaffected.

### Summer 2026 Learning Docs

The detailed project notes live in a separate portfolio repo:

- Nmap scanning labs – see `summer-hacking-projects/docs/nmap-port-scanning*.md`
- DNS enumeration labs – see `summer-hacking-projects/docs/dig-dns-enumeration.md`
  
#### How web checks run

When `WEB_TARGET_FILE` exists, the scanner runs **optional** web tools per target and degrades gracefully when a tool is not installed — a missing tool logs a warning and the workflow continues:

- **`curl`** reachability check (HTTP status code) — always available.
- **`whatweb`** technology fingerprint — used only if installed.
- **`nikto`** baseline web server checks (default plugins, time-limited, non-interactive) — used only if installed.
- **`nmap` HTTP NSE scripts** (`http-title`, `http-headers`, `http-server-header`, `http-methods`) against the URL's host/port — safe/default scripts only.

All scans are **safe/default**: no brute-force, authenticated attacks, or destructive NSE categories. Per-target output is written under `reports/web-<timestamp>/` and summarised in `reports/latest-vulnerability-report.md` under a **Web Application Targets** section (target URL, tool used, HTTP status, and artifact paths). A machine-readable summary is written to `reports/web-<timestamp>.json`.

Optional web tools on Kali:

```bash
sudo apt update
sudo apt install -y whatweb nikto
```

#### Proxmox management caution

Proxmox is **management infrastructure**, not an intentionally vulnerable target — keep its checks read-only/default and never run destructive or authenticated attacks against it. Also note that **Proxmox normally serves HTTPS on port 8006**. The provided `http://192.168.2.53:8006` URL is kept as-is for now; **if HTTP checks fail or redirect, switch the `Proxmox` line in `web-targets.txt` to `https://192.168.2.53:8006`** (the self-signed cert is fine — `curl`/`nmap` are run with TLS verification relaxed for lab use).

### Setting up NmapAutomator on Kali (manual, not yet wired in)

[NmapAutomator](https://github.com/21y4d/nmapAutomator) is **not currently installed** on the Kali scanner VM, and it is intentionally **not** wired into the scheduled workflow. If you want it for ad-hoc, interactive enumeration, install it manually on Kali:

```bash
sudo git clone https://github.com/21y4d/nmapAutomator.git /opt/nmapAutomator
sudo ln -sf /opt/nmapAutomator/nmapAutomator.sh /usr/local/bin/nmapAutomator
nmapAutomator --help
# Example ad-hoc run against a single host:
nmapAutomator -H 192.168.3.60 -t Port
```

Run it manually only against hosts you own. It is left out of the scheduled job so the automated scan stays lightweight and non-breaking; revisit wiring it in later only as an optional, non-fatal step.

### Fast runner setup when Proxmox paste is painful

The self-hosted runner lives on the **Kali attacker VM (`192.168.3.149`)** so it can reach the scan targets on the lab network. If you cannot easily copy/paste into the Proxmox web console, SSH into the Kali VM from another machine and run a single curl pipeline. Get the registration token from **GitHub repo → Settings → Actions → Runners → New self-hosted runner**, then:

```bash
ssh <user>@192.168.3.149
curl -fsSL https://raw.githubusercontent.com/gideon930-linux/homelab-cyber-range/main/scripts/setup_github_runner_ubuntu.sh -o setup_runner.sh
bash setup_runner.sh <RUNNER_TOKEN>
```

The script is apt-based and works on Kali (Debian-based) as well as Ubuntu. It installs dependencies, downloads the latest runner, configures it for this repo, and starts it as a systemd service.

### Setup

1. Install a self-hosted GitHub Actions runner on the **Kali attacker VM (`192.168.3.149`)** so it can reach the homelab scan targets. The Kali VM is the scanner/attacker host — do **not** run the runner on the Ubuntu Server or Windows 11 VMs, since those are scan targets.
2. Install scanner dependencies on the runner:

   ```bash
   sudo apt update
   sudo apt install -y nmap jq curl python3
   # Optional web-check tooling (web checks degrade gracefully if absent):
   sudo apt install -y whatweb nikto
   ```

3. Edit `target.txt` and list your existing VM IPs or hostnames (one per line). Edit `web-targets.txt` and list any web application URLs as `LABEL = URL`.
4. In GitHub repository **Settings → Variables**, add:

   - `DISCOVERY_CIDRS` — optional, e.g. `192.168.1.0/24`, used to detect unrecognized hosts on the LAN.
   - `RUN_NESSUS` — `true` or `false`.

5. In GitHub repository **Settings → Secrets**, add (only if using Nessus):

   - `NESSUS_URL` — e.g. `https://192.168.1.50:8834`
   - `NESSUS_SCAN_ID` — numeric ID of an existing Nessus scan
   - `NESSUS_ACCESS_KEY`
   - `NESSUS_SECRET_KEY`

### Schedule

The workflow runs every weekday at `11:00 UTC` (7:00 AM America/New_York during DST). GitHub Actions cron schedules are UTC-only — during standard time, change the cron to `0 12 * * 1-5` to keep it at 7:00 AM Eastern.

### Manual run

You can also trigger the workflow manually from the Actions tab. Manual inputs let you temporarily override `DISCOVERY_CIDRS` and choose whether to run Nessus.

### OS detection and root privileges

Nmap OS detection (`-O`) sends raw packets and therefore requires root privileges. The self-hosted runner on the Kali VM runs as a normal (non-root) user, so forcing `-O` makes Nmap abort with:

```
TCP/IP fingerprinting requires root privileges.
QUITTING!
```

To keep scheduled scans reliable, the scanner now decides at runtime whether OS detection can run:

- **Service/version detection (`-sV`) always runs** — this never needs root.
- **OS detection (`-O`) is added only when privileges allow it:**
  - the scanner is running as root, **or**
  - `NMAP_USE_SUDO=true` is set **and** passwordless sudo is available (`sudo -n` succeeds).
- Otherwise the scanner logs a warning and continues **without** `-O`. The scan still succeeds; the **OS Guess** column in the report is simply empty (`n/a`) for that run.

This behavior is controlled by two optional environment variables:

| Variable | Default | Effect |
|---|---|---|
| `ENABLE_OS_DETECTION` | `auto` | `auto`/`true` attempts OS detection when privileges allow; `false` disables it entirely. |
| `NMAP_USE_SUDO` | `false` | When `true`, allows the scanner to prefix Nmap with `sudo -n` for OS detection (only if passwordless sudo works). |

The scanner never prompts for an interactive sudo password, so a missing or password-protected sudo just falls back to a scan without OS guesses instead of hanging or failing.

#### Optionally enabling OS detection with passwordless sudo

If you want OS guesses back in the report, grant the runner user passwordless sudo for `nmap` on the Kali VM:

```bash
# As root / via the Proxmox console:
echo "<runner-user> ALL=(root) NOPASSWD: /usr/bin/nmap" | sudo tee /etc/sudoers.d/nmap-scan
sudo chmod 0440 /etc/sudoers.d/nmap-scan
sudo visudo -cf /etc/sudoers.d/nmap-scan   # validate syntax
```

Then set the workflow/job env var `NMAP_USE_SUDO=true` (for example via GitHub repository **Settings → Variables** and wiring it into the workflow `env:` block, or by exporting it before running the script locally). With passwordless sudo in place and `NMAP_USE_SUDO=true`, scheduled scans will run `sudo -n nmap ... -O ...` and repopulate the OS Guess column.

### Troubleshooting

- **`TCP/IP fingerprinting requires root privileges. QUITTING!`** — The runner is non-root and OS detection was forced. The scanner now skips `-O` automatically in this case and continues; if you still see this, ensure you are on the current version of `scripts/homelab_vuln_scan.sh`. To restore OS guesses, follow the passwordless-sudo steps above.
- **OS Guess column shows `n/a`** — Expected when OS detection is skipped (no root / sudo). Service and port data are unaffected.

### Notes

- Only scan networks and systems you own or have permission to test.
- Nessus integration launches and reads an existing Nessus scan ID — maintain the actual scan policy in Nessus.
- Review net-new ports before accepting them as normal. A newly opened service may be intentional, but should still be documented.
