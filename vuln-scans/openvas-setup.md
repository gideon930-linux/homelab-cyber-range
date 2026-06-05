# OpenVAS / Greenbone Scanner Setup

## Objective

Set up a dedicated vulnerability scanner in my homelab using Greenbone Community Edition (OpenVAS) and use it to run regular scans against my lab subnet.

## Scanner VM

- Platform: Proxmox
- VM name: openvas-scanner
- OS: (Ubuntu Server LTS or Debian)  ← update once chosen
- Resources: 2–4 vCPUs, 4–8 GB RAM, 40–80 GB disk
- Network: Connected to the isolated lab VLAN behind OPNsense

## Installation Steps (high level)

1. Install the OS on the `openvas-scanner` VM.
2. Install Greenbone / OpenVAS packages.
3. Run the initial setup so vulnerability feeds are updated.
4. Access the Greenbone web interface from my browser.
5. Create a scan configuration for my lab subnet (e.g. 192.168.3.0/24).

## Scan Schedule

- Frequency: Weekly full scan of the lab subnet.
- Extra scans: After major OS/application updates or new lab services.

## What I Will Document Here

- Screenshots of the scanner dashboard (with sensitive details removed).
- Example scan results and key findings.
- Notes on how I fixed vulnerabilities and hardened the systems.
