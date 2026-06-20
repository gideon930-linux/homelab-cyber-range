# Nmap Port Scanning – Focused TCP Scans (Session 2)

This document is a continuation of `nmap-port-scanning.md`, focusing on:
- Full TCP port scans (`-p-`)
- Service/version detection (`-sV`)
- Aggressive scans with OS detection (`-A -T4`)
- Timing tweaks (`--min-rate`, `--max-retries`)

## Focused Port Scans and Scan Types

### Full TCP port scan (`-p-`)

```bash
sudo nmap -p- 192.168.2.127
```

**Summary**

- Scope: All 65,535 TCP ports.
- Result: Only three ports discovered as open:
  - `3000/tcp` – open (Juice Shop)
  - `8081/tcp` – open (DVWA)
  - `8082/tcp` – open (WebGoat)
- All other TCP ports reported as **filtered** (no response), indicating OPNsense is dropping unsolicited traffic by default.
- Runtime examples:
  - ~791 seconds (long run)
  - ~141 seconds (later run)

**Takeaway:** A full-port scan confirmed there are no unexpected open TCP ports on the OPNsense WAN IP beyond the three intentionally exposed web apps.

---

### Service and version detection (`-sV`)

```bash
sudo nmap -sV -p 3000,8081,8082 192.168.2.127
```

**Summary**

- Scope: Only the three known web ports.
- Detected services:

| Port    | State | Service | Version / Notes                            |
|---------|-------|---------|--------------------------------------------|
| 3000/tcp | open | http    | OWASP Juice Shop (banner not fully parsed) |
| 8081/tcp | open | http    | Apache httpd 2.4.25 (Debian) – DVWA        |
| 8082/tcp | open | http    | Apache Tomcat 10.1.36 – WebGoat            |

- Nmap could not confidently label port 3000’s service and displayed `ppp?`, but the HTTP banner clearly shows the OWASP Juice Shop HTML and headers.

**Takeaway:** Version detection confirmed that each WAN-exposed port maps to exactly one of the lab’s vulnerable web apps, with Apache and Tomcat versions visible for later vuln research.

---

### Aggressive scan with OS detection and scripts (`-A -T4`)

```bash
sudo nmap -A -T4 -p 3000,8081,8082 192.168.2.127
```

**Summary**

- Adds: OS detection, traceroute, and default NSE scripts on the selected ports.
- HTTP findings:
  - Port 3000:
    - HTTP 200 OK response containing the OWASP Juice Shop HTML title and description.
    - Security-related headers present (e.g., `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`, `Feature-Policy`, `Access-Control-Allow-Origin: *`).
  - Port 8081:
    - `http-title`: “Login :: Damn Vulnerable Web Application (DVWA)”
    - `http-server-header`: `Apache/2.4.25 (Debian)`
    - `http-robots.txt`: one disallowed entry (`/`)
    - Cookie analysis: `PHPSESSID` without `httponly` flag set.
  - Port 8082:
    - `http-title`: HTTP Status 404 – Not Found (Tomcat default 404 page)
    - Server: Apache Tomcat 10.1.36
- OS detection:
  - Nmap could not reliably fingerprint the OS because it could not find a closed TCP port (all non-open ports appear **filtered**).
  - Traceroute distance: 1 hop to `192.168.2.127` (as expected on the local LAN).

**Takeaway:** Aggressive scanning gave rich application-level details (titles, headers, cookies) but still could not determine OS due to strict firewall filtering, which is acceptable in this lab context.

---

### Full-port scan with custom timing (`--min-rate` / `--max-retries`)

```bash
sudo nmap -p- --min-rate 5000 --max-retries 2 192.168.2.127
```

**Summary**

- Purpose: Demonstrate faster full-port scanning with rate controls.
- Parameters:
  - `--min-rate 5000` – try to send at least 5000 packets per second.
  - `--max-retries 2` – limit the number of retries per probe on slow/non-responsive ports.
- Result:
  - Same three open ports discovered:
    - `3000/tcp` – open
    - `8081/tcp` – open
    - `8082/tcp` – open
  - All other ports remained **filtered**.
  - Scan completed in ~26 seconds instead of several minutes.

**Takeaway:** On a controlled LAN, tightening `--min-rate` and `--max-retries` dramatically reduced scan time while still finding the same open ports. This would be too aggressive on fragile or production networks, but it is ideal for a home cyber range experiment.

---

## Focused Scan Lessons Learned

- Full TCP scans (`-p-`) are useful for verifying that no unexpected ports are exposed, at the cost of longer scan times.
- Service/version detection (`-sV`) and aggressive scans (`-A`) provide much more context about web applications and headers, which is exactly what a web app pentester needs.
- Strict firewall rules on OPNsense cause most ports to appear as **filtered**, which can limit OS detection but is good defensive posture.
- Timing controls (`--min-rate`, `--max-retries`) can massively speed up scans in a homelab while still returning accurate open-port information.
