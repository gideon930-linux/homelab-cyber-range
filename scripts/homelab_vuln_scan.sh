#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
WORKSPACE_ROOT="${WORKSPACE_ROOT:-$(pwd)}"
TARGET_FILE="${TARGET_FILE:-target.txt}"
BASELINE_FILE="${BASELINE_FILE:-scan-state/baseline.json}"
REPORT_DIR="${REPORT_DIR:-reports}"
DISCOVERY_CIDRS="${DISCOVERY_CIDRS:-}"
NMAP_TIMING="${NMAP_TIMING:-T3}"
NMAP_EXTRA_ARGS="${NMAP_EXTRA_ARGS:-}"
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

log "Running Nmap scan against ${#expected_targets[@]} expected target entries"
nmap -"$NMAP_TIMING" -sV -O --open -oX "$nmap_xml" $NMAP_EXTRA_ARGS "${expected_targets[@]}"

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

log "Creating diffed findings and Markdown report"
python3 - "$nmap_json" "$nessus_json" "$BASELINE_FILE" "$discovered_json" "$TARGET_FILE" "$finding_json" "$report_md" "$timestamp_utc" "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" <<'PY'
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

