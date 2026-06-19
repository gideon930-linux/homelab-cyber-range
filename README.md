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

### Reconnaissance and Enumeration Labs

These notes document introductory reconnaissance work performed against services exposed through the lab firewall for learning and documentation purposes.

- **Nmap port scanning notes:** [`docs/nmap-port-scanning.md`](docs/nmap-port-scanning.md)
- **dig DNS enumeration notes:** [`docs/dig-dns-enumeration.md`](docs/dig-dns-enumeration.md)

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

- `target.txt` — expected VM inventory. Add your current VM IPs or hostnames here.
- `scripts/homelab_vuln_scan.sh` — scanner script (Nmap + optional Nessus API).
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
   ```

3. Edit `target.txt` and list your existing VM IPs or hostnames (one per line).
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

### Notes

- Only scan networks and systems you own or have permission to test.
- Nessus integration launches and reads an existing Nessus scan ID — maintain the actual scan policy in Nessus.
- Review net-new ports before accepting them as normal. A newly opened service may be intentional, but should still be documented.
