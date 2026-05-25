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
- ## Pentesting in the lab

I use this environment to practice ethical hacking and blue-team defense:

- Kali Linux as an attack box
- Intentionally vulnerable targets (e.g., DVWA, Metasploitable, test web apps)
- OPNsense rules to keep the lab isolated from my home network
- Tools such as Nmap, Metasploit, Burp Suite, and Wireshark

All testing is performed only on systems I own or have explicit permission to test.

## Homelab Vulnerability Scanner

This repository includes an automated weekday vulnerability scanner for the homelab VMs running on Proxmox. It reads expected VM targets from `target.txt`, runs Nmap against them, optionally launches an existing Nessus scan through the Nessus API, and posts a structured report to a GitHub issue.

The workflow runs on a **self-hosted GitHub Actions runner** because Proxmox/private homelab networks (e.g. `192.168.x.x`) are not reachable from GitHub-hosted runners.

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

### Setup

1. Install a self-hosted GitHub Actions runner on a VM that can reach your homelab network.
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
