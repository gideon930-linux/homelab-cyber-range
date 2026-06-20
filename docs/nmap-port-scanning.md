# Nmap Port Scanning – Host Discovery Basic Ports - OPNsense WAN Web Services

## Objective

Document external reconnaissance against services exposed through the OPNsense WAN interface in my homelab, using Nmap for host discovery and basic port scanning.

## Lab Context

- Date/time: 2026-06-19 16:16 EDT
- Attacker host: `ajones` (main PC) on `192.168.2.121`
- Scan network: `192.168.2.0/24`
- Target of interest: OPNsense WAN IP `192.168.2.127` (port-forwarding to internal lab web apps)

## Commands Executed

### 1. Host discovery on the /24

```bash
nmap -sn 192.168.2.0/24
```

### 2. Default TCP scan of OPNsense WAN IP

```bash
sudo nmap -p- 192.168.2.127
```

### 3. Targeted port scan for common infra + lab web ports

```bash
sudo nmap -p 22,80,443,3000,8081,8082 192.168.2.127
```

## Raw Output (Key Excerpts)

### 1. Host discovery

```text
Nmap scan report for 192.168.2.127
Host is up (0.00040s latency).Nmap scan report for _gateway (192.168.2.1)
Host is up (0.00062s latency).
Nmap scan report for 192.168.2.50
Host is up (0.00077s latency).
Nmap scan report for pve.lan (192.168.2.53)
Host is up (0.00015s latency).
Nmap scan report for 192.168.2.90
Host is up (0.00059s latency).
Nmap scan report for vault.lan (192.168.2.100)
Host is up (0.00047s latency).
Nmap scan report for 192.168.2.109
Host is up (0.0065s latency).
Nmap scan report for 192.168.2.110
Host is up (0.016s latency).
Nmap scan report for 192.168.2.111
Host is up (0.047s latency).
Nmap scan report for 192.168.2.117
Host is up (0.0042s latency).
Nmap scan report for ajones (192.168.2.121)
Host is up (0.00025s latency).
Nmap scan report for 192.168.2.122
Host is up (0.00081s latency).
Nmap scan report for 192.168.2.126
Host is up (0.0011s latency).
Nmap done: 256 IP addresses (12 hosts up) scanned in 2.63 seconds

```

### 2. Default scan of 192.168.2.127

```text
Nmap scan report for 192.168.2.127
Host is up (0.00049s latency)
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
3000/tcp open  ppp
8081/tcp open  blackice-icecap
8082/tcp open  blackice-alerts
MAC Address: BC:24:11:F6:BF:9E (Unknown)
```

### 3. Targeted port scan (22, 80, 443, 3000, 8081, 8082)

```text
Nmap scan report for 192.168.2.127
Host is up (0.00045s latency).

PORT     STATE    SERVICE
22/tcp   filtered ssh
80/tcp   filtered http
443/tcp  filtered https
3000/tcp open     ppp
8081/tcp open     blackice-icecap
8082/tcp open     blackice-alerts
MAC Address: BC:24:11:F6:BF:9E (Unknown)
```

## Interpreted Findings

### Host discovery

- 12 hosts responded on `192.168.2.0/24`, including:
  - Gateway: `192.168.2.1` (`_gateway`)
  - Proxmox: `192.168.2.53` (`pve.lan`)
  - Vault server: `192.168.2.100` (`vault.lan`)
  - Attacker workstation: `ajones` (`192.168.2.121`)
- The target OPNsense WAN IP `192.168.2.127` was confirmed up and reachable.

### Port scan of 192.168.2.127

- Open TCP ports:
  - `3000/tcp` – mapped to the Juice Shop web app
  - `8081/tcp` – mapped to DVWA
  - `8082/tcp` – mapped to WebGoat
- Ports `22`, `80`, and `443` are **filtered**, indicating firewall rules on OPNsense are blocking direct SSH/HTTP/HTTPS to the WAN IP.

## Conclusions / Next Steps

- OPNsense WAN rules and NAT configuration are correctly exposing only the intended lab web ports (3000, 8081, 8082) to the home network.
- SSH and standard web ports are intentionally filtered, reducing the external attack surface.
- Next steps:
  - Run `nmap -sV -p 3000,8081,8082 192.168.2.127` to fingerprint the exact services.
  - Use HTTP NSE scripts (`http-title`, `http-server-header`, `http-security-headers`) to gather more web recon details.
