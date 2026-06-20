# Nmap Port Scanning – NSE Scripts and Output Files (Session 3)

This document continues my Nmap work against the OPNsense WAN IP `192.168.2.127`, focusing on HTTP NSE scripts and saving scan output for later analysis.

## 1. HTTP NSE Scripts Against Lab Web Apps

### 1.1 Quick HTTP title and server header enumeration

```bash
sudo nmap -p 3000,8081,8082 \
  --script=http-title,http-server-header \
  192.168.2.127
```

**Purpose**

- Use lightweight NSE scripts to grab HTTP titles and server headers on the WAN‑exposed web ports.
- Quickly confirm which web apps are exposed and what software stack they run.

**Summary of this run**

- Host `192.168.2.127` responded with the three expected open TCP ports:
  - `3000/tcp` – Juice Shop (HTTP service on a non‑standard port)
  - `8081/tcp` – DVWA (Apache httpd on port 8081)
  - `8082/tcp` – WebGoat (Apache Tomcat on port 8082)
- Nmap completed in ~0.18 seconds on the local LAN.

> Note: In this particular run, the scripts did not print detailed titles/headers to the terminal, but using `http-title` and `http-server-header` is still the right pattern for quick reconnaissance against web apps.

---

### 1.2 HTTP security header inspection on Juice Shop

```bash
sudo nmap -p 3000 \
  --script=http-security-headers \
  192.168.2.127
```

**Purpose**

- Analyze security‑related HTTP headers on the Juice Shop instance listening on port 3000.
- Check for common protections like `X-Content-Type-Options`, `X-Frame-Options`, and similar.

**Summary of this run**

- Host: `192.168.2.127`
- Port: `3000/tcp` – open
- The `http-security-headers` script ran against the Juice Shop web service.
- In earlier `-sV` / `-A` scans, Nmap already showed headers such as:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Feature-Policy: payment 'self'`
  - `Access-Control-Allow-Origin: *`

**Takeaway**

- NSE HTTP scripts such as `http-title`, `http-server-header`, and `http-security-headers` provide a fast way to enrich basic port scans with application‑level context, which is especially useful for web application testing.

---

## 2. Saving Nmap Output for the Repository

### 2.1 Version detection with output in all formats

```bash
sudo nmap -sV -p 3000,8081,8082 -oA scans/opnsense-wan-web 192.168.2.127
```

**Purpose**

- Run service/version detection on all three WAN‑exposed web ports.
- Save the results in `.nmap`, `.gnmap`, and `.xml` formats for later parsing and documentation.

**Summary**

- Host `192.168.2.127` is up and reachable.
- Detected services:

| Port    | State | Service | Version                     |
|---------|-------|---------|-----------------------------|
| 3000/tcp | open | http    | OWASP Juice Shop (banner)   |
| 8081/tcp | open | http    | Apache httpd 2.4.25 (Debian)|
| 8082/tcp | open | http    | Apache Tomcat 10.1.36       |

- Nmap could not match a built‑in service fingerprint for port 3000 and labeled it as `ppp?`, but the HTTP response clearly shows the OWASP Juice Shop HTML and headers.

**Files created**

The `-oA scans/opnsense-wan-web` option generated:

- `scans/opnsense-wan-web.nmap`  – human‑readable Nmap output
- `scans/opnsense-wan-web.gnmap` – grep‑friendly format
- `scans/opnsense-wan-web.xml`   – XML suitable for conversion to CSV or further scripting

In my repo:

```text
scans/
  opnsense-wan-web.gnmap
  opnsense-wan-web.nmap
  opnsense-wan-web.xml
  opnsense-wan-web.txt   # extra text export
```

**Takeaway**

- Saving scans with `-oA` makes it easy to:
  - Attach real scan artifacts to the homelab repo for documentation.
  - Parse XML into CSV or markdown tables later using scripts or tools.
  - Re‑review the exact scan results without rerunning long full‑port scans.

---

## 3. Lessons Learned in Session 3

- NSE HTTP scripts are a natural next step after basic port and service discovery, adding web‑specific context (titles, headers, cookies, security headers).
- The `-oA` option is ideal for homelab documentation because it produces multiple formats in one command, which can be reused for reporting and automation.
- Even when Nmap cannot perfectly fingerprint a service (e.g., port 3000 as `ppp?`), the raw banner often has all the clues needed to identify the application (Juice Shop in this case).
