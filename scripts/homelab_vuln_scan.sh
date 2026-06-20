#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$(pwd)}"
TARGET_FILE="${TARGET_FILE:-target.txt}"
WEB_TARGET_FILE="${WEB_TARGET_FILE:-web-targets.txt}"
BASELINE_FILE="${BASELINE_FILE:-scan-state/baseline.json}"
REPORT_DIR="${REPORT_DIR:-reports}"
DISCOVERY_CIDRS="${DISCOVERY_CIDRS:-}"
NMAP_TIMING="${NMAP_TIMING:-T3}"
NMAP_EXTRA_ARGS="${NMAP_EXTRA_ARGS:-}"
ENABLE_OS_DETECTION="${ENABLE_OS_DETECTION:-auto}"
NMAP_USE_SUDO="${NMAP_USE_SUDO:-false}"
RUN_NESSUS="${RUN_NESSUS:-true}"
NESSUS_URL="${NESSUS_URL:-}"
NESSUS_SCAN_ID="${NESSUS_SCAN_ID:-}"
NESSUS_ACCESS_KEY="${NESSUS_ACCESS_KEY:-}"
NESSUS_SECRET_KEY="${NESSUS_SECRET_KEY:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-local/homelab}"
GITHUB_RUN_ID="${GITHUB_RUN_ID:-local}"

mkdir -p "$REPORT_DIR" "$(dirname "$BASELINE_FILE")"

timestamp_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
stamp="$(date -u +"%Y%m%dT%H%M%SZ")"
nmap_xml="$REPORT_DIR/nmap-$stamp.xml"
nmap_json="$REPORT_DIR/nmap-$stamp.json"
nessus_json="$REPORT_DIR/nessus-$stamp.json"
finding_json="$REPORT_DIR/findings-$stamp.json"
web_json="$REPORT_DIR/web-$stamp.json"
web_output_dir="$REPORT_DIR/web-$stamp"
report_md="$REPORT_DIR/vulnerability-report-$stamp.md"
latest_report="$REPORT_DIR/latest-vulnerability-report.md"
latest_findings="$REPORT_DIR/latest-findings.json"

log() {
  printf '[%s] %s\n' "$SCRIPT_NAME" "$*" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "Missing required command: $1"
    exit 2
  fi
}

normalize_target_file() {
  local input="$1"
  grep -vE '^\s*(#|$)' "$input" | sed 's/[[:space:]]*$//' | sort -u
}

if [[ ! -f "$TARGET_FILE" ]]; then
  log "Target file not found: $TARGET_FILE"
  exit 2
fi

require_command nmap
require_command python3
require_command jq
require_command curl

mapfile -t expected_targets < <(normalize_target_file "$TARGET_FILE")
if [[ "${#expected_targets[@]}" -eq 0 ]]; then
  log "No targets found in $TARGET_FILE"
  exit 2
fi

# OS detection (-O) requires raw-packet privileges (effectively root). On a
# non-root self-hosted runner nmap aborts with "TCP/IP fingerprinting requires
# root privileges. QUITTING!", which fails the whole scheduled scan. Decide
# whether OS detection can run, and how, without ever blocking on interactive
# sudo.
nmap_prefix=()
os_detection_args=()
os_detection_note="disabled"

want_os_detection=false
case "${ENABLE_OS_DETECTION,,}" in
  false|no|off|0)
    want_os_detection=false
    ;;
  *)
    want_os_detection=true
    ;;
esac

if [[ "$want_os_detection" == "true" ]]; then
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    os_detection_args=(-O)
    os_detection_note="enabled (running as root)"
  elif [[ "${NMAP_USE_SUDO,,}" =~ ^(true|yes|on|1)$ ]] && command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    nmap_prefix=(sudo -n)
    os_detection_args=(-O)
    os_detection_note="enabled (via passwordless sudo)"
  else
    log "WARNING: OS detection (-O) requires root privileges. Continuing service/version scan WITHOUT -O."
    log "WARNING: To enable OS guesses, run the scanner as root, or configure passwordless sudo and set NMAP_USE_SUDO=true."
    os_detection_note="skipped (no root privileges; OS guesses will be empty)"
  fi
else
  os_detection_note="skipped (ENABLE_OS_DETECTION=$ENABLE_OS_DETECTION)"
fi

log "Running Nmap scan against ${#expected_targets[@]} expected target entries (OS detection: $os_detection_note)"
# shellcheck disable=SC2086
"${nmap_prefix[@]}" nmap -"$NMAP_TIMING" -sV "${os_detection_args[@]}" --open -oX "$nmap_xml" $NMAP_EXTRA_ARGS "${expected_targets[@]}"

log "Parsing Nmap XML"
python3 - "$nmap_xml" "$nmap_json" <<'PY'
import json
import sys
import xml.etree.ElementTree as ET

xml_path, out_path = sys.argv[1], sys.argv[2]
root = ET.parse(xml_path).getroot()
hosts = {}

for host in root.findall("host"):
    status = host.find("status")
    if status is not None and status.attrib.get("state") != "up":
        continue

    addresses = []
    mac = None
    vendor = None
    for addr in host.findall("address"):
        addr_value = addr.attrib.get("addr")
        addr_type = addr.attrib.get("addrtype")
        if not addr_value:
            continue
        if addr_type == "mac":
            mac = addr_value
            vendor = addr.attrib.get("vendor")
        else:
            addresses.append(addr_value)

    if not addresses and mac:
        addresses.append(mac)
    if not addresses:
        continue

    host_key = addresses[0]
    hostnames = [
        h.attrib.get("name")
        for h in host.findall("./hostnames/hostname")
        if h.attrib.get("name")
    ]

    os_matches = []
    for match in host.findall("./os/osmatch"):
        name = match.attrib.get("name")
        accuracy = match.attrib.get("accuracy")
        if name:
            os_matches.append({"name": name, "accuracy": accuracy})

    ports = []
    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None or state.attrib.get("state") != "open":
            continue
        service = port.find("service")
        port_data = {
            "protocol": port.attrib.get("protocol", ""),
            "port": int(port.attrib.get("portid", "0")),
            "service": service.attrib.get("name", "") if service is not None else "",
            "product": service.attrib.get("product", "") if service is not None else "",
            "version": service.attrib.get("version", "") if service is not None else "",
            "extrainfo": service.attrib.get("extrainfo", "") if service is not None else "",
        }
        ports.append(port_data)

    hosts[host_key] = {
        "addresses": addresses,
        "hostnames": hostnames,
        "mac": mac,
        "vendor": vendor,
        "os_matches": os_matches[:3],
        "ports": sorted(ports, key=lambda p: (p["protocol"], p["port"])),
    }

with open(out_path, "w", encoding="utf-8") as f:
    json.dump({"hosts": hosts}, f, indent=2, sort_keys=True)
PY

discovered_json="$REPORT_DIR/discovered-$stamp.json"
if [[ -n "$DISCOVERY_CIDRS" ]]; then
  log "Running discovery scan for unrecognized hosts: $DISCOVERY_CIDRS"
  discovery_gnmap="$REPORT_DIR/discovery-$stamp.gnmap"
  # shellcheck disable=SC2086
  nmap -sn -oG "$discovery_gnmap" $DISCOVERY_CIDRS >/dev/null
  awk '/Status: Up/{print $2}' "$discovery_gnmap" | sort -u | jq -R -s 'split("\n") | map(select(length > 0))' > "$discovered_json"
else
  printf '[]\n' > "$discovered_json"
fi

if [[ "$RUN_NESSUS" == "true" && -n "$NESSUS_URL" && -n "$NESSUS_SCAN_ID" && -n "$NESSUS_ACCESS_KEY" && -n "$NESSUS_SECRET_KEY" ]]; then
  log "Requesting Nessus scan launch for scan ID $NESSUS_SCAN_ID"
  curl -skS -X POST \
    -H "X-ApiKeys: accessKey=$NESSUS_ACCESS_KEY; secretKey=$NESSUS_SECRET_KEY" \
    "$NESSUS_URL/scans/$NESSUS_SCAN_ID/launch" >/dev/null || true

  log "Waiting for Nessus scan to complete"
  for _ in $(seq 1 120); do
    nessus_status="$(curl -skS -H "X-ApiKeys: accessKey=$NESSUS_ACCESS_KEY; secretKey=$NESSUS_SECRET_KEY" "$NESSUS_URL/scans/$NESSUS_SCAN_ID" | jq -r '.info.status // "unknown"')"
    if [[ "$nessus_status" == "completed" ]]; then
      break
    fi
    sleep 30
  done

  log "Downloading Nessus scan summary"
  curl -skS \
    -H "X-ApiKeys: accessKey=$NESSUS_ACCESS_KEY; secretKey=$NESSUS_SECRET_KEY" \
    "$NESSUS_URL/scans/$NESSUS_SCAN_ID" > "$nessus_json"
else
  log "Skipping Nessus scan. Set Nessus secrets and NESSUS_SCAN_ID to enable it."
  printf '{"skipped": true, "reason": "Nessus API configuration not complete"}\n' > "$nessus_json"
fi

# --- Lightweight web application checks -------------------------------------
# Runs only when WEB_TARGET_FILE exists. Optional tools (whatweb, nikto, nmap
# HTTP scripts) are used when installed and skipped with a warning otherwise.
# This block must never fail the overall workflow: every external command is
# guarded with `|| true`, and missing tools are logged and skipped.
web_results=()
if [[ -f "$WEB_TARGET_FILE" ]]; then
  mkdir -p "$web_output_dir"
  have_whatweb=false; command -v whatweb >/dev/null 2>&1 && have_whatweb=true
  have_nikto=false;   command -v nikto   >/dev/null 2>&1 && have_nikto=true
  have_nmap=false;    command -v nmap    >/dev/null 2>&1 && have_nmap=true

  if [[ "$have_whatweb" == false && "$have_nikto" == false && "$have_nmap" == false ]]; then
    log "WARNING: No web scanning tools (whatweb/nikto/nmap) found. Skipping web checks."
  else
    log "Running lightweight web checks (whatweb=$have_whatweb nikto=$have_nikto nmap=$have_nmap)"
  fi

  web_index=0
  while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
    line="${raw_line%%$'\r'}"
    # Strip leading/trailing whitespace.
    line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$line" || "$line" == \#* ]] && continue
    [[ "$line" != *=* ]] && continue

    label="$(printf '%s' "${line%%=*}" | sed 's/[[:space:]]*$//')"
    url="$(printf '%s' "${line#*=}" | sed 's/^[[:space:]]*//')"
    [[ -z "$url" ]] && continue

    web_index=$((web_index + 1))
    safe_label="$(printf '%s' "$label" | tr -c 'A-Za-z0-9._-' '_' | sed 's/_\{2,\}/_/g')"
    [[ -z "$safe_label" ]] && safe_label="target"
    slug="${web_index}-${safe_label}"

    # Parse host and port from the URL for nmap HTTP scripts.
    scheme="${url%%://*}"
    rest="${url#*://}"
    hostport="${rest%%/*}"
    web_host="${hostport%%:*}"
    if [[ "$hostport" == *:* ]]; then
      web_port="${hostport##*:}"
    elif [[ "$scheme" == "https" ]]; then
      web_port=443
    else
      web_port=80
    fi

    status="no-tool"
    tool_used="none"
    artifact_ref="none"

    # 1) HTTP reachability via curl (already a required command).
    http_code="$(curl -skS -o /dev/null -w '%{http_code}' --max-time 15 "$url" 2>/dev/null || true)"
    [[ -z "$http_code" ]] && http_code="000"

    artifacts=()

    if [[ "$have_whatweb" == true ]]; then
      ww_out="$web_output_dir/${slug}.whatweb.txt"
      if whatweb --no-errors -a 1 --color=never "$url" >"$ww_out" 2>&1; then
        status="completed"
      else
        status="completed-with-warnings"
      fi
      tool_used="whatweb"
      artifacts+=("$ww_out")
    fi

    if [[ "$have_nikto" == true ]]; then
      nk_out="$web_output_dir/${slug}.nikto.txt"
      # -nointeractive keeps nikto non-blocking; default plugins only (safe).
      nikto -h "$url" -nointeractive -maxtime 120s -output "$nk_out" -Format txt >/dev/null 2>&1 || true
      [[ -s "$nk_out" ]] || printf 'nikto produced no output for %s\n' "$url" >"$nk_out"
      tool_used="${tool_used}+nikto"; tool_used="${tool_used#none+}"
      status="completed"
      artifacts+=("$nk_out")
    fi

    if [[ "$have_nmap" == true ]]; then
      nm_out="$web_output_dir/${slug}.nmap-http.txt"
      # Safe, default HTTP NSE scripts only — no brute/dos/exploit categories.
      nmap -Pn -p "$web_port" \
        --script "http-title,http-headers,http-server-header,http-methods" \
        "$web_host" -oN "$nm_out" >/dev/null 2>&1 || true
      [[ -s "$nm_out" ]] || printf 'nmap http scripts produced no output for %s:%s\n' "$web_host" "$web_port" >"$nm_out"
      tool_used="${tool_used}+nmap-http"; tool_used="${tool_used#none+}"
      [[ "$status" == "no-tool" ]] && status="completed"
      artifacts+=("$nm_out")
    fi

    if [[ "${#artifacts[@]}" -gt 0 ]]; then
      artifact_ref="$(IFS=';'; printf '%s' "${artifacts[*]}")"
    fi

    web_results+=("$(printf '%s\t%s\t%s\t%s\t%s\t%s' \
      "$label" "$url" "$tool_used" "$status" "$http_code" "$artifact_ref")")
  done < "$WEB_TARGET_FILE"

  # Emit a JSON summary of web results for the report generator.
  : > "$web_json.tmp"
  for entry in "${web_results[@]:-}"; do
    [[ -z "$entry" ]] && continue
    printf '%s\n' "$entry" >> "$web_json.tmp"
  done
  python3 - "$web_json.tmp" "$web_json" "$WEB_TARGET_FILE" <<'PY'
import json, sys
from pathlib import Path
tsv_path, out_path, web_target_file = sys.argv[1:]
results = []
p = Path(tsv_path)
if p.exists():
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        while len(parts) < 6:
            parts.append("")
        results.append({
            "label": parts[0],
            "url": parts[1],
            "tool": parts[2],
            "status": parts[3],
            "http_code": parts[4],
            "artifact": parts[5],
        })
Path(out_path).write_text(
    json.dumps({"enabled": True, "target_file": web_target_file, "results": results},
               indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
  rm -f "$web_json.tmp"
else
  log "Web target file not found ($WEB_TARGET_FILE); skipping web application checks."
  printf '{"enabled": false, "results": []}\n' > "$web_json"
fi

log "Creating diffed findings and Markdown report"
python3 - "$nmap_json" "$nessus_json" "$BASELINE_FILE" "$discovered_json" "$TARGET_FILE" "$finding_json" "$report_md" "$timestamp_utc" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" "$web_json" <<'PY'
import ipaddress
import json
import sys
from pathlib import Path

(
    nmap_json,
    nessus_json,
    baseline_file,
    discovered_json,
    target_file,
    finding_json,
    report_md,
    timestamp_utc,
    github_repository,
    github_run_id,
    web_json,
) = sys.argv[1:]

def load_json(path, default):
    p = Path(path)
    if not p.exists():
        return default
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return default

def port_id(port):
    return f"{port.get('protocol','tcp')}/{port.get('port')}"

def target_entries(path):
    entries = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        entries.append(item)
    return entries

def is_expected_host(host, entries):
    for entry in entries:
        if host == entry:
            return True
        try:
            if "/" in entry and ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False

nmap_data = load_json(nmap_json, {"hosts": {}})
baseline = load_json(baseline_file, {"hosts": {}})
nessus = load_json(nessus_json, {"skipped": True})
discovered = load_json(discovered_json, [])
web_data = load_json(web_json, {"enabled": False, "results": []})
web_results = web_data.get("results", []) if isinstance(web_data, dict) else []
targets = target_entries(target_file)

current_hosts = nmap_data.get("hosts", {})
baseline_hosts = baseline.get("hosts", {})

new_hosts = sorted(set(current_hosts) - set(baseline_hosts))
new_ports = []
closed_ports = []

for host, data in current_hosts.items():
    current_ports = {port_id(p): p for p in data.get("ports", [])}
    baseline_ports = {
        port_id(p): p
        for p in baseline_hosts.get(host, {}).get("ports", [])
    }
    for new_port_id in sorted(set(current_ports) - set(baseline_ports)):
        new_ports.append({
            "host": host,
            "port": new_port_id,
            "details": current_ports[new_port_id],
        })
    for closed_port_id in sorted(set(baseline_ports) - set(current_ports)):
        closed_ports.append({
            "host": host,
            "port": closed_port_id,
            "previous_details": baseline_ports[closed_port_id],
        })

unrecognized_hosts = sorted(
    host for host in discovered
    if host not in current_hosts and not is_expected_host(host, targets)
)

nessus_findings = []
if not nessus.get("skipped"):
    for vuln in nessus.get("vulnerabilities", []):
        count = int(vuln.get("count") or 0)
        severity = int(vuln.get("severity") or 0)
        if count > 0 and severity > 0:
            nessus_findings.append({
                "plugin_id": vuln.get("plugin_id"),
                "plugin_name": vuln.get("plugin_name"),
                "severity": severity,
                "count": count,
                "vpr_score": vuln.get("vpr_score"),
            })

summary = {
    "generated_at_utc": timestamp_utc,
    "repository": github_repository,
    "github_run_id": github_run_id,
    "new_hosts": new_hosts,
    "unrecognized_hosts": unrecognized_hosts,
    "new_ports": new_ports,
    "closed_ports": closed_ports,
    "nessus_findings": nessus_findings,
    "host_count": len(current_hosts),
    "web_targets": web_results,
    "web_enabled": bool(web_data.get("enabled")) if isinstance(web_data, dict) else False,
}

with Path(finding_json).open("w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, sort_keys=True)

def md_escape(value):
    return str(value).replace("|", "\\|")

lines = []
lines.append("# Homelab Vulnerability Scan Report")
lines.append("")
lines.append(f"- **Generated UTC:** {timestamp_utc}")
lines.append(f"- **Repository:** `{github_repository}`")
lines.append(f"- **GitHub run ID:** `{github_run_id}`")
lines.append(f"- **Hosts scanned:** {len(current_hosts)}")
lines.append(f"- **Net-new expected hosts:** {len(new_hosts)}")
lines.append(f"- **Unrecognized discovered hosts:** {len(unrecognized_hosts)}")
lines.append(f"- **Net-new open ports:** {len(new_ports)}")
lines.append(f"- **Nessus findings:** {len(nessus_findings) if not nessus.get('skipped') else 'Skipped'}")
lines.append(f"- **Web targets checked:** {len(web_results) if web_data.get('enabled') else 'Skipped'}")
lines.append("")

lines.append("## Executive Summary")
lines.append("")
if new_hosts or unrecognized_hosts or new_ports or nessus_findings:
    lines.append("Action is recommended. This run found new scan inventory changes, newly exposed services, unrecognized live hosts, or Nessus findings.")
else:
    lines.append("No net-new hosts, unrecognized live hosts, newly opened ports, or Nessus findings were detected in this run.")
lines.append("")

lines.append("## Net-New Expected Hosts")
lines.append("")
if new_hosts:
    for host in new_hosts:
        data = current_hosts.get(host, {})
        names = ", ".join(data.get("hostnames") or []) or "n/a"
        ports = ", ".join(port_id(p) for p in data.get("ports", [])) or "none detected"
        lines.append(f"- **{host}**: hostnames `{names}`; open ports `{ports}`")
else:
    lines.append("- None")
lines.append("")

lines.append("## Unrecognized Live Hosts")
lines.append("")
if unrecognized_hosts:
    lines.append("These hosts were found in `DISCOVERY_CIDRS` but are not listed in `target.txt`. Validate whether each one belongs in your homelab inventory.")
    lines.append("")
    for host in unrecognized_hosts:
        lines.append(f"- **{host}**: status `needs owner / purpose / approval`")
else:
    lines.append("- None")
lines.append("")

lines.append("## Net-New Open Ports")
lines.append("")
if new_ports:
    lines.append("| Host | Port | Service | Product | Version | Tracking Status |")
    lines.append("|---|---:|---|---|---|---|")
    for item in new_ports:
        d = item["details"]
        lines.append(
            f"| {md_escape(item['host'])} | {md_escape(item['port'])} | "
            f"{md_escape(d.get('service') or 'unknown')} | {md_escape(d.get('product') or '')} | "
            f"{md_escape(d.get('version') or '')} | Needs review |"
        )
else:
    lines.append("- None")
lines.append("")

lines.append("## Closed Ports Since Last Baseline")
lines.append("")
if closed_ports:
    for item in closed_ports:
        lines.append(f"- **{item['host']}**: `{item['port']}` no longer appears open")
else:
    lines.append("- None")
lines.append("")

lines.append("## Nessus Findings")
lines.append("")
if nessus.get("skipped"):
    lines.append("- Nessus was skipped because API settings were not fully configured.")
elif nessus_findings:
    lines.append("| Severity | Plugin ID | Finding | Count | VPR | Tracking Status |")
    lines.append("|---:|---:|---|---:|---:|---|")
    for item in sorted(nessus_findings, key=lambda x: (-x["severity"], str(x["plugin_name"]))):
        lines.append(
            f"| {item.get('severity')} | {item.get('plugin_id')} | {md_escape(item.get('plugin_name'))} | "
            f"{item.get('count')} | {item.get('vpr_score') or ''} | Needs triage |"
        )
else:
    lines.append("- None")
lines.append("")

lines.append("## Host Inventory Snapshot")
lines.append("")
if current_hosts:
    lines.append("| Host | Hostnames | OS Guess | Open Ports |")
    lines.append("|---|---|---|---|")
    for host, data in sorted(current_hosts.items()):
        hostnames = ", ".join(data.get("hostnames") or []) or "n/a"
        os_guess = "n/a"
        if data.get("os_matches"):
            first = data["os_matches"][0]
            os_guess = f"{first.get('name')} ({first.get('accuracy')}%)"
        ports = ", ".join(port_id(p) for p in data.get("ports", [])) or "none"
        lines.append(f"| {md_escape(host)} | {md_escape(hostnames)} | {md_escape(os_guess)} | {md_escape(ports)} |")
else:
    lines.append("- No live expected targets detected.")
lines.append("")

lines.append("## Web Application Targets")
lines.append("")
if not web_data.get("enabled"):
    lines.append("- Web application checks were skipped (no `web-targets.txt` present).")
elif web_results:
    lines.append("Lightweight, safe/default web checks (whatweb / nikto / nmap HTTP scripts). "
                 "See artifact files for full output.")
    lines.append("")
    lines.append("| Target | URL | Tool(s) | HTTP | Status | Artifact(s) |")
    lines.append("|---|---|---|---:|---|---|")
    for item in web_results:
        lines.append(
            f"| {md_escape(item.get('label') or 'n/a')} | {md_escape(item.get('url') or '')} | "
            f"{md_escape(item.get('tool') or 'none')} | {md_escape(item.get('http_code') or '000')} | "
            f"{md_escape(item.get('status') or 'unknown')} | {md_escape(item.get('artifact') or 'none')} |"
        )
else:
    lines.append("- Web target file was present but produced no scannable entries.")
lines.append("")

lines.append("## Remediation Checklist")
lines.append("")
lines.append("- [ ] Confirm every unrecognized host has an owner and purpose.")
lines.append("- [ ] Confirm every net-new open port is expected and documented.")
lines.append("- [ ] Disable unused services or restrict access with firewall rules.")
lines.append("- [ ] Triage Nessus findings by severity and exploitability.")
lines.append("- [ ] Update `target.txt` and commit baseline changes after validation.")
lines.append("")

Path(report_md).write_text("\n".join(lines) + "\n", encoding="utf-8")
PY

cp "$report_md" "$latest_report"
cp "$finding_json" "$latest_findings"

log "Updating baseline file"
python3 - "$nmap_json" "$BASELINE_FILE" "$timestamp_utc" <<'PY'
import json
import sys
from pathlib import Path

nmap_json, baseline_file, timestamp_utc = sys.argv[1:]
with open(nmap_json, "r", encoding="utf-8") as f:
    data = json.load(f)
data["last_updated_utc"] = timestamp_utc
Path(baseline_file).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

log "Report written to $report_md"
log "Latest report copied to $latest_report"

