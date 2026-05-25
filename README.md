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
