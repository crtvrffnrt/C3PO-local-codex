#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import mimetypes
import html
import ipaddress
import hashlib
import json
import os
import shlex
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RUN_ROOT = ROOT / "runs"
MAX_ACTIVE_IPV4_ADDRESSES = 65536
MAX_TOP_HOSTS = 10
FRITZBOX_IP = "192.168.100.1"
FAST_PORTS = "21,22,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900-5909,5985,5986,6379,8000,8080,8443,9200,9300"
DISCOVERY_TCP_PORTS = "53,88,135,139,389,445,464,593,636,3268,3269,5985"
SAFE_NUCLEI_TAGS = "exposure,misconfig,panel,tech,ssl,tls,http"
SAFE_NUCLEI_SEVERITIES = "info,low,medium,high"
WEB_PORTS = {80, 443, 8000, 8080, 8443, 9443, 5000, 5601, 9200}
HIGH_IMPACT_PORTS = {21, 22, 23, 53, 88, 111, 135, 139, 389, 443, 445, 636, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 9300}
MANAGEMENT_PORTS = {21, 22, 23, 53, 88, 111, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 5986, 8000, 8080, 8443, 9200, 9300, 2049, 1433, 1521, 3306, 5432, 6379}
MAX_TCP_DISCOVERY_ADDRESSES = 1024
EXCLUDED_IPV4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
TUNNEL_PREFIXES = ("tun", "tap", "wg")
DC_PORTS = {53, 88, 135, 389, 445, 464, 593, 636, 3268, 3269, 5985}
DC_SRV_RECORDS = (
    "_ldap._tcp.dc._msdcs.{domain}",
    "_kerberos._tcp.{domain}",
)
SUPPORTED_SCREENSHOT_BROWSERS = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "msedge",
)

PORT_LABELS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    111: "rpcbind",
    135: "MSRPC",
    139: "NetBIOS",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    464: "Kerberos pwd",
    593: "RPC over HTTP",
    636: "LDAPS",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
    9200: "Elasticsearch",
    9300: "Elastic transport",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM TLS",
    6379: "Redis",
}

SERVICE_TOOLTIPS = {
    21: "FTP is commonly unencrypted and should usually be disabled or replaced with a secure alternative unless explicitly required.",
    22: "Remote shell access should be restricted to trusted admin networks or required management hosts. Validate business need and harden authentication.",
    23: "Telnet transmits data without encryption and should generally be disabled.",
    53: "DNS service exposure is expected on resolvers but should be validated for recursion behavior, zone leakage, and administrative separation.",
    80: "Internal web interfaces should require authentication, be patched, and avoid default credentials or exposed admin panels.",
    88: "Kerberos exposure can indicate identity infrastructure. Validate the host's role and restrict lateral reachability.",
    111: "rpcbind is often used by NFS and other RPC services. Restrict it to trusted clients and validate whether it is required.",
    135: "MSRPC exposure often accompanies Windows remote management. Restrict access to trusted admin systems.",
    139: "NetBIOS/SMB exposure should be limited to required systems. Validate signing, guest access, and share permissions.",
    389: "LDAP should be limited to systems that genuinely need directory access. Validate anonymous bind behavior and hardening.",
    443: "Internal web interfaces should require authentication, be patched, and avoid default credentials or exposed admin panels.",
    445: "SMB exposure should be limited to required systems. Validate patching, signing, guest access, and share permissions.",
    464: "Kerberos password change or related directory traffic should only be reachable where directory services are expected.",
    593: "RPC over HTTP / EPMAP exposure should be validated for necessity and restricted to management contexts.",
    636: "LDAPS should be limited to directory clients that need it and validated for certificate and binding hardening.",
    8000: "Alternative web ports often host admin consoles, dev services, or embedded device interfaces. Validate ownership, authentication, and update status.",
    8080: "Alternative web ports often host admin consoles, dev services, or embedded device interfaces. Validate ownership, authentication, and update status.",
    8443: "Alternative web ports often host admin consoles, dev services, or embedded device interfaces. Validate ownership, authentication, and update status.",
    9200: "Elasticsearch should generally not be broadly reachable from user segments. Validate authentication and access controls.",
    9300: "Elastic transport exposure should be tightly restricted to cluster nodes only.",
    1433: "MSSQL exposure should be limited to application or admin hosts and protected by strong authentication and patching.",
    1521: "Oracle database exposure should be limited to approved clients and hardened according to vendor guidance.",
    2049: "NFS exports should be restricted to known clients and validated for root squashing and share permissions.",
    2375: "Unauthenticated Docker exposure is high risk and should be removed or isolated immediately.",
    2376: "Docker TLS exposure should be limited to trusted admin systems and verified for certificate-based access.",
    3306: "MySQL exposure should be limited to approved clients and validated for authentication and patching.",
    3389: "RDP is a high-impact remote administration service. Restrict access, require strong authentication, and validate whether it must be reachable from this network segment.",
    5432: "PostgreSQL exposure should be limited to approved clients and validated for authentication and patching.",
    5601: "Kibana often exposes analytics or admin features. Validate authentication and whether it should be reachable from this segment.",
    5900: "VNC should be restricted to trusted management hosts and protected with strong authentication.",
    5985: "WinRM enables remote Windows administration. Restrict to administrative systems and monitor usage.",
    5986: "WinRM over TLS enables remote Windows administration. Restrict to administrative systems and monitor usage.",
    6379: "Redis should not usually be broadly reachable. Validate authentication and bind/listen settings.",
}


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    state: str = "open"


@dataclass
class Host:
    ip: str
    hostname: str = ""
    netbios_name: str = ""
    smb_name: str = ""
    domain_or_workgroup: str = ""
    mdns_name: str = ""
    mac: str = ""
    vendor: str = ""
    sources: set[str] = field(default_factory=set)
    services: dict[int, Service] = field(default_factory=dict)
    score: int = 0
    ranking_reasons: list[str] = field(default_factory=list)
    role_guess: str = ""
    role_confidence: str = "low"
    deep_scanned: bool = False
    dc_candidate: bool = False
    dc_status: str = "none"
    dc_confidence: str = "low"
    dc_evidence: list[str] = field(default_factory=list)
    screenshot_path: str = ""
    screenshot_embedded: bool = False
    screenshot_data_uri: str = ""
    screenshot_mime: str = ""


@dataclass
class RouteEntry:
    destination: str
    network: ipaddress.IPv4Network
    via: str = ""
    dev: str = ""
    src: str = ""
    metric: str = ""
    scope: str = ""
    proto: str = ""
    table: str = "main"
    raw: str = ""
    source: str = ""


@dataclass
class RouteScope:
    interface: str
    requested_network: str
    addresses: list[str]
    candidate_networks: list[ipaddress.IPv4Network]
    validated_networks: list[ipaddress.IPv4Network]
    excluded_networks: list[str]
    overlap_warnings: list[dict[str, Any]]
    route_get_samples: list[dict[str, Any]]
    route_text: dict[str, str]
    route_entries: list[RouteEntry]


def normalize_identity_value(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    return text.strip(" \t\r\n,;.")


def basedn_to_domain(value: str) -> str:
    labels = []
    for part in re.split(r"\s*,\s*", str(value or "")):
        if part.upper().startswith("DC="):
            label = normalize_identity_value(part.split("=", 1)[1])
            if label:
                labels.append(label)
    return ".".join(labels)


def extract_identity_hints(text: str) -> dict[str, str]:
    hints: dict[str, str] = {}
    if not text:
        return hints
    patterns = [
        ("hostname", r"\b(?:dns\s+)?hostname\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)+)"),
        ("hostname", r"\bfqdn\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)+)"),
        ("hostname", r"\bhost\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)+)"),
        ("netbios_name", r"\b(?:computer|netbios)(?:\s+name|_name)?\s*[:=]\s*([A-Za-z0-9._-]+)"),
        ("smb_name", r"\b(?:smb|computer|netbios)(?:\s+name|_name)?\s*[:=]\s*([A-Za-z0-9._-]+)"),
        ("domain_or_workgroup", r"\b(?:domain|workgroup)\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*)"),
    ]
    for key, pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match and key not in hints:
            hints[key] = normalize_identity_value(match.group(1))
    match = re.search(r"\bbaseDN\s*=\s*([A-Za-z0-9=,._-]+)", text, re.I)
    if match and "domain_or_workgroup" not in hints:
        domain = basedn_to_domain(match.group(1))
        if domain:
            hints["domain_or_workgroup"] = domain
    if "hostname" not in hints:
        match = re.search(r"\b(?:dns\s+name|name)\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)+)", text, re.I)
        if match:
            hints["hostname"] = normalize_identity_value(match.group(1))
    if "netbios_name" not in hints and "hostname" in hints:
        short = hints["hostname"].split(".", 1)[0]
        if short:
            hints["netbios_name"] = short
    return hints


def apply_identity_hints(host: Host, text: str, source: str = "") -> None:
    hints = extract_identity_hints(text)
    hostname = hints.get("hostname", "")
    netbios_name = hints.get("netbios_name", "")
    smb_name = hints.get("smb_name", "")
    domain_or_workgroup = hints.get("domain_or_workgroup", "")
    if hostname and not host.hostname:
        host.hostname = hostname
    if netbios_name and not host.netbios_name:
        host.netbios_name = netbios_name
    if smb_name and not host.smb_name:
        host.smb_name = smb_name
    if domain_or_workgroup and not host.domain_or_workgroup:
        host.domain_or_workgroup = domain_or_workgroup
    if source.startswith("mdns") and not host.mdns_name:
        host.mdns_name = hostname or netbios_name or smb_name
    if source.startswith(("smb", "nmb", "nbt")) and not host.smb_name:
        host.smb_name = host.netbios_name or smb_name or netbios_name
    if not host.hostname and host.netbios_name and not source.startswith("smb"):
        host.hostname = host.netbios_name


def flatten_nmap_script(script: ET.Element) -> str:
    parts = []
    output = normalize_identity_value(script.get("output", ""))
    if output:
        parts.append(output)

    def walk(elem: ET.Element) -> None:
        key = normalize_identity_value(elem.get("key") or elem.tag)
        text = normalize_identity_value(elem.text or "")
        if key and text:
            parts.append(f"{key}: {text}")
        for child in elem:
            walk(child)

    for child in script:
        walk(child)
    return " ".join(parts)


def add_nmap_host_metadata(host: Host, node: ET.Element) -> None:
    hostnames = node.find("hostnames")
    if hostnames is not None:
        names = [normalize_identity_value(h.get("name", "")) for h in hostnames.findall("hostname") if normalize_identity_value(h.get("name", ""))]
        if names and not host.hostname:
            host.hostname = names[0]
            if "." in host.hostname and not host.netbios_name:
                host.netbios_name = host.hostname.split(".", 1)[0]
    hostscript = node.find("hostscript")
    if hostscript is None:
        return
    for script in hostscript.findall("script"):
        script_id = normalize_identity_value(script.get("id", ""))
        text = flatten_nmap_script(script)
        if text:
            apply_identity_hints(host, text, source=f"nmap:{script_id or 'hostscript'}")
        if script_id == "smb-os-discovery":
            host.sources.add("nmap-smb-os-discovery")
            if not host.smb_name:
                match = re.search(r"\bcomputer name\s*[:=]\s*([A-Za-z0-9._-]+)", text, re.I)
                if match:
                    host.smb_name = normalize_identity_value(match.group(1))
                    if not host.netbios_name:
                        host.netbios_name = host.smb_name
            if not host.domain_or_workgroup:
                match = re.search(r"\b(?:domain|workgroup)\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*)", text, re.I)
                if match:
                    host.domain_or_workgroup = normalize_identity_value(match.group(1))
        elif script_id == "nbstat":
            host.sources.add("nmap-nbstat")
            match = re.search(r"\b([A-Za-z0-9._-]+)\s+<00>\s+-\s+[AB]\s+<ACTIVE>", text)
            if match and not host.netbios_name:
                host.netbios_name = normalize_identity_value(match.group(1))
            match = re.search(r"\b(?:workgroup|domain)\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*)", text, re.I)
            if match and not host.domain_or_workgroup:
                host.domain_or_workgroup = normalize_identity_value(match.group(1))


def port_label(port: int, service_name: str = "") -> str:
    if 5900 <= port <= 5909:
        return "VNC"
    if port in PORT_LABELS:
        return PORT_LABELS[port]
    cleaned = normalize_identity_value(service_name).replace("-", " ")
    return cleaned.title() if cleaned else "TCP"


def service_display(service: Service) -> str:
    return f"{service.port}/{port_label(service.port, service.name)}"


def service_tooltip(port: int) -> str:
    return SERVICE_TOOLTIPS.get(port, "Validate business need, restrict exposure to the smallest trusted set of hosts, and confirm patching and authentication settings.")


def service_recommendation(port: int) -> str:
    if port in SERVICE_TOOLTIPS:
        return SERVICE_TOOLTIPS[port]
    return "Validate business need, restrict exposure to the smallest trusted set of hosts, and confirm patching and authentication settings."


def extract_domain_from_text(text: str) -> str:
    match = re.search(r"\b(?:domain|workgroup)\s*[:=]\s*([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)*)", text or "", re.I)
    if match:
        return normalize_identity_value(match.group(1))
    match = re.search(r"\bbaseDN\s*=\s*([A-Za-z0-9=,._-]+)", text or "", re.I)
    if match:
        domain = basedn_to_domain(match.group(1))
        if domain:
            return domain
    return ""


def host_identity_summary(host: Host) -> str:
    items = [
        f"Hostname: {host.hostname or 'unknown'}",
        f"NetBIOS: {host.netbios_name or 'unknown'}",
    ]
    if host.smb_name and host.smb_name not in {host.netbios_name, host.hostname}:
        items.append(f"SMB: {host.smb_name}")
    if host.domain_or_workgroup:
        items.append(f"Domain/workgroup: {host.domain_or_workgroup}")
    if host.mdns_name and host.mdns_name not in {host.hostname, host.netbios_name}:
        items.append(f"mDNS: {host.mdns_name}")
    return " | ".join(items)


def host_service_summary(host: Host, limit: int = 4) -> str:
    services = sorted(host.services.values(), key=lambda svc: (svc.port not in HIGH_IMPACT_PORTS, svc.port))
    labels = [service_display(service) for service in services[:limit]]
    return ", ".join(labels) if labels else "none"


def host_service_chips(host: Host, limit: int = 6) -> str:
    services = sorted(host.services.values(), key=lambda svc: (svc.port not in HIGH_IMPACT_PORTS, svc.port))
    chips = []
    for service in services[:limit]:
        chips.append(
            f"<span class='svc-chip' title='{esc(service_tooltip(service.port))}'>{esc(service_display(service))}</span>"
        )
    if len(services) > limit:
        chips.append(f"<span class='svc-chip svc-chip-muted'>+{len(services) - limit} more</span>")
    return "".join(chips) or "<span class='svc-chip svc-chip-muted'>No open ports recorded</span>"


def host_dc_badge_text(host: Host, dc_candidates: dict[str, dict[str, Any]]) -> str:
    status = host.dc_status
    if status == "none" and host.ip in dc_candidates:
        status = str(dc_candidates[host.ip].get("status", "candidate") or "candidate")
    if status == "confirmed":
        return "Domain controller"
    if status == "candidate":
        return "DC candidate"
    return ""


def load_screenshot_data_uri(image_path: Path) -> tuple[str, str]:
    if not image_path.exists() or not image_path.is_file():
        return "", ""
    try:
        data = image_path.read_bytes()
    except OSError:
        return "", ""
    if not data:
        return "", ""
    mime = mimetypes.guess_type(image_path.name)[0] or ""
    if mime not in {"image/png", "image/jpeg"}:
        if data.startswith(b"\x89PNG\r\n\x1a\n"):
            mime = "image/png"
        elif data[:3] == b"\xff\xd8\xff":
            mime = "image/jpeg"
        else:
            return "", ""
    encoded = base64.b64encode(data).decode("ascii")
    return f"data:{mime};base64,{encoded}", mime


def embed_screenshots(top_hosts: list[Host], outdir: Path) -> dict[str, Any]:
    summary = {"attempted": 0, "embedded": 0, "missing": [], "status": "no"}
    for host in top_hosts:
        host.screenshot_embedded = False
        host.screenshot_data_uri = ""
        host.screenshot_mime = ""
        if not host.screenshot_path:
            continue
        summary["attempted"] += 1
        image_path = outdir / host.screenshot_path
        data_uri, mime = load_screenshot_data_uri(image_path)
        if data_uri:
            host.screenshot_embedded = True
            host.screenshot_data_uri = data_uri
            host.screenshot_mime = mime
            summary["embedded"] += 1
        else:
            summary["missing"].append(host.ip)
    if summary["attempted"] == 0:
        summary["status"] = "no"
    elif summary["embedded"] == summary["attempted"]:
        summary["status"] = "yes"
    elif summary["embedded"] > 0:
        summary["status"] = "partial"
    else:
        summary["status"] = "no"
    return summary


def top_host_findings(findings: list[dict[str, Any]], host: Host) -> list[dict[str, Any]]:
    return host_findings(findings, host)[:3]


def normalized_findings_host(value: Any) -> str:
    text = normalize_identity_value(value)
    if not text:
        return ""
    parsed = urlsplit(text)
    if parsed.hostname:
        return parsed.hostname
    return text


def command_title_for_host_command(host: Host, service: Service, dc_candidates: dict[str, dict[str, Any]]) -> tuple[str, str, str]:
    if service.port in WEB_PORTS:
        url = service_url(host.ip, service.port)
        return (
            f"Check web interface on {service_display(service)}",
            f"curl -k -I --connect-timeout 5 --max-time 10 {shlex.quote(url)}",
            "10s",
        )
    if service.port in {445, 139}:
        return (
            f"Check SMB exposure on {service_display(service)}",
            f"nmap -Pn -n -p 139,445 --script smb-os-discovery,smb-protocols,smb-security-mode --script-timeout 20s {shlex.quote(host.ip)}",
            "20s",
        )
    if service.port in {389, 636}:
        return (
            f"Check LDAP exposure on {service_display(service)}",
            f"nmap -Pn -n -p 389,636 --script ldap-rootdse --script-timeout 20s {shlex.quote(host.ip)}",
            "20s",
        )
    if service.port == 3389:
        return (
            "Check RDP exposure",
            f"nmap -Pn -n -p 3389 --script rdp-enum-encryption --script-timeout 20s {shlex.quote(host.ip)}",
            "20s",
        )
    if service.port == 5985:
        return (
            "Check WinRM exposure",
            f"curl -k -I --connect-timeout 5 --max-time 10 http://{shlex.quote(host.ip)}:5985/wsman",
            "10s",
        )
    if service.port == 5986:
        return (
            "Check WinRM TLS exposure",
            f"curl -k -I --connect-timeout 5 --max-time 10 https://{shlex.quote(host.ip)}:5986/wsman",
            "10s",
        )
    if service.port == 111:
        return (
            "Check rpcbind exposure",
            f"nc -vz -w 3 {shlex.quote(host.ip)} 111",
            "3s",
        )
    if service.port == 2049:
        return (
            "Check NFS exports",
            f"showmount -e {shlex.quote(host.ip)}",
            "15s",
        )
    return (
        f"Confirm open port {service_display(service)}",
        f"nc -vz -w 3 {shlex.quote(host.ip)} {service.port}",
        "3s",
    )


def host_verification_commands(host: Host, dc_candidates: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = []
    seen = set()
    for service in sorted(host.services.values(), key=lambda item: (item.port not in HIGH_IMPACT_PORTS, item.port, item.name)):
        title, command, timeout = command_title_for_host_command(host, service, dc_candidates)
        if command in seen:
            continue
        commands.append({"label": title, "command": command, "timeout": timeout, "port": str(service.port), "service": service_display(service)})
        seen.add(command)
    dc_status = host.dc_status
    dc_domain = ""
    if dc_status == "none" and host.ip in dc_candidates:
        dc_status = str(dc_candidates[host.ip].get("status", "candidate") or "candidate")
    if host.ip in dc_candidates:
        dc_domain = normalize_identity_value(dc_candidates[host.ip].get("domain_name", ""))
    if not dc_domain and host.domain_or_workgroup and "." in host.domain_or_workgroup:
        dc_domain = normalize_identity_value(host.domain_or_workgroup)
    if dc_status in {"candidate", "confirmed"}:
        if dc_domain:
            commands.append({"label": "Confirm LDAP SRV records", "command": f"dig _ldap._tcp.dc._msdcs.{shlex.quote(dc_domain)} SRV", "timeout": "5s", "port": "", "service": "DNS"})
            commands.append({"label": "Confirm Kerberos SRV records", "command": f"dig _kerberos._tcp.{shlex.quote(dc_domain)} SRV", "timeout": "5s", "port": "", "service": "DNS"})
    return commands[:8]


def command_record_status(record: dict[str, Any]) -> str:
    if record.get("timed_out") or record.get("exit_code") == 124:
        return "partial"
    exit_code = record.get("exit_code")
    if exit_code in {0, None}:
        return "complete"
    return "failed"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def info(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def write_text_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


def write_json_file(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Interface-scoped local-network scanner")
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-c", "--cidr", default="")
    parser.add_argument("--authorized", "--i-own-this-scope", action="store_true", dest="authorized")
    parser.add_argument("--codex-model", default="")
    parser.add_argument("--codex-reasoning", default="")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def run_command(cmd: list[str], outdir: Path, name: str, timeout: int, check: bool = False) -> dict[str, Any]:
    logs = outdir / "logs"
    logs.mkdir(exist_ok=True)
    stdout_path = logs / f"{name}.stdout.txt"
    stderr_path = logs / f"{name}.stderr.txt"
    start = time.time()
    record = {
        "name": name,
        "argv": cmd,
        "redacted_argv": redact_argv(cmd),
        "start": utc_now(),
        "timeout_seconds": timeout,
        "stdout_path": str(stdout_path.relative_to(outdir)),
        "stderr_path": str(stderr_path.relative_to(outdir)),
        "exit_code": None,
        "timed_out": False,
        "error": "",
    }
    try:
        completed = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=check)
        stdout_path.write_text(coerce_text(completed.stdout), encoding="utf-8", errors="replace")
        stderr_path.write_text(coerce_text(completed.stderr), encoding="utf-8", errors="replace")
        record["exit_code"] = completed.returncode
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(coerce_text(exc.stdout), encoding="utf-8", errors="replace")
        stderr_path.write_text(coerce_text(exc.stderr), encoding="utf-8", errors="replace")
        record["exit_code"] = 124
        record["timed_out"] = True
        record["error"] = f"process timed out after {timeout}s"
    except Exception as exc:
        stderr_path.write_text(str(exc), encoding="utf-8")
        record["exit_code"] = 1
        record["error"] = str(exc)
    record["end"] = utc_now()
    record["duration_seconds"] = round(time.time() - start, 3)
    append_jsonl(outdir / "commands.jsonl", record)
    return record


def redact_argv(argv: list[str]) -> list[str]:
    sensitive_next = {"--password", "--hash", "--pfx-pass", "--pfx-base64", "--pem-key", "--kdc-host"}
    redacted = []
    skip = False
    for idx, item in enumerate(argv):
        if skip:
            redacted.append("<redacted>")
            skip = False
            continue
        redacted.append(item)
        if item in sensitive_next and idx + 1 < len(argv):
            skip = True
    return redacted


def coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def append_jsonl(path: Path, obj: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(obj, sort_keys=True) + "\n")


def safe_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version != 4:
        return False
    return ip.is_private and not any(ip in excluded for excluded in EXCLUDED_IPV4)


def is_tunnel_interface(iface: str) -> bool:
    return iface.startswith(TUNNEL_PREFIXES)


def ip_in_scope(ip: str, networks: list[ipaddress.IPv4Network]) -> bool:
    try:
        address = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return any(address in network for network in networks)


def ipv4_scope_allowed(net: ipaddress.IPv4Network) -> bool:
    if not net.is_private:
        return False
    if any(net.subnet_of(excluded) or net == excluded for excluded in EXCLUDED_IPV4):
        return False
    return net.prefixlen > 0


def ipv4_active_allowed(net: ipaddress.IPv4Network) -> bool:
    return ipv4_scope_allowed(net) and net.num_addresses <= MAX_ACTIVE_IPV4_ADDRESSES


def ip_sort_key(value: str) -> tuple[int, tuple[int, ...]]:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return (ip.version, tuple(ip.packed))


def load_json_command(cmd: list[str], timeout: int = 20) -> Any:
    completed = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    return json.loads(completed.stdout)


def parse_ipv4_route_line(line: str, source: str = "", table: str = "main") -> RouteEntry | None:
    parts = line.split()
    if not parts:
        return None
    if len(parts) >= 8 and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[0]) and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[1]) and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[2]):
        destination, gateway, genmask, metric, iface = parts[0], parts[1], parts[2], parts[4], parts[7]
        try:
            network = ipaddress.ip_network(f"{destination}/{genmask}", strict=False)
        except ValueError:
            return None
        via = "" if gateway == "0.0.0.0" else gateway
        return RouteEntry(destination=str(network), network=network, via=via, dev=iface, metric=metric, table=table, raw=line, source=source)
    head = parts[0]
    if head in {"unreachable", "blackhole", "prohibit", "throw", "nat"}:
        return None
    destination = head
    try:
        network = ipaddress.ip_network("0.0.0.0/0" if head == "default" else head, strict=False)
    except ValueError:
        return None
    via = ""
    dev = ""
    src = ""
    metric = ""
    scope = ""
    proto = ""
    index = 1
    while index < len(parts):
        token = parts[index]
        if token in {"via", "dev", "src", "metric", "scope", "proto", "table"} and index + 1 < len(parts):
            value = parts[index + 1]
            if token == "via":
                via = value
            elif token == "dev":
                dev = value
            elif token == "src":
                src = value
            elif token == "metric":
                metric = value
            elif token == "scope":
                scope = value
            elif token == "proto":
                proto = value
            elif token == "table":
                table = value
            index += 2
            continue
        index += 1
    return RouteEntry(destination=destination, network=network, via=via, dev=dev, src=src, metric=metric, scope=scope, proto=proto, table=table, raw=line, source=source)


def parse_ipv4_route_table(text: str, source: str = "", table: str = "main") -> list[RouteEntry]:
    entries = []
    for line in text.splitlines():
        entry = parse_ipv4_route_line(line.strip(), source=source, table=table)
        if entry is not None:
            entries.append(entry)
    return entries


def representative_ip(network: ipaddress.IPv4Network) -> str:
    if network.prefixlen >= 32:
        return str(network.network_address)
    offset = 1 if network.num_addresses > 2 else 0
    return str(ipaddress.IPv4Address(int(network.network_address) + offset))


def network_label(network: ipaddress.IPv4Network) -> str:
    return str(network)


def route_get_dev(route_output: str) -> str:
    match = re.search(r"\bdev\s+(\S+)", route_output)
    return match.group(1) if match else ""


def route_get_via(route_output: str) -> str:
    match = re.search(r"\bvia\s+(\S+)", route_output)
    return match.group(1) if match else ""


def route_candidates_from_context(addr_data: list[dict[str, Any]], route_entries: list[RouteEntry], iface: str) -> list[ipaddress.IPv4Network]:
    candidates: dict[str, ipaddress.IPv4Network] = {}
    for item in addr_data:
        for addr in item.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if not local or prefix is None:
                continue
            try:
                net = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
            except ValueError:
                continue
            if isinstance(net, ipaddress.IPv4Network) and ipv4_scope_allowed(net):
                candidates[str(net)] = net
    for entry in route_entries:
        if entry.dev == iface and isinstance(entry.network, ipaddress.IPv4Network) and ipv4_scope_allowed(entry.network):
            candidates[str(entry.network)] = entry.network
    return sorted(candidates.values(), key=lambda n: (int(n.network_address), n.prefixlen))


def validate_route_scope(
    iface: str,
    addr_data: list[dict[str, Any]],
    route_dev_entries: list[RouteEntry],
    route_main_entries: list[RouteEntry],
    outdir: Path,
    requested_network: ipaddress.IPv4Network | None = None,
) -> RouteScope:
    candidate_networks = route_candidates_from_context(addr_data, route_dev_entries + route_main_entries, iface)
    evaluation_networks = list(candidate_networks)
    if requested_network is not None and requested_network not in evaluation_networks:
        evaluation_networks.append(requested_network)
    route_get_samples: list[dict[str, Any]] = []
    overlap_warnings: list[dict[str, Any]] = []
    excluded_networks: list[str] = []
    validated: list[ipaddress.IPv4Network] = []
    main_by_network: dict[str, list[RouteEntry]] = {}
    for entry in route_main_entries:
        if isinstance(entry.network, ipaddress.IPv4Network):
            main_by_network.setdefault(str(entry.network), []).append(entry)
    for network in evaluation_networks:
        rep = representative_ip(network)
        record = run_command(["ip", "-4", "route", "get", rep], outdir, f"route_get_{sanitize(network_label(network))}", timeout=15)
        output = (outdir / record["stdout_path"]).read_text(encoding="utf-8", errors="replace").strip()
        stderr = (outdir / record["stderr_path"]).read_text(encoding="utf-8", errors="replace").strip()
        effective_dev = route_get_dev(output)
        effective_via = route_get_via(output)
        route_get_samples.append({
            "network": str(network),
            "representative_ip": rep,
            "stdout": output,
            "stderr": stderr,
            "exit_code": record["exit_code"],
            "timed_out": record["timed_out"],
            "effective_dev": effective_dev,
            "effective_via": effective_via,
        })
        competing = [entry for entry in main_by_network.get(str(network), []) if entry.dev and entry.dev != iface]
        if competing:
            overlap_warnings.append({
                "network": str(network),
                "representative_ip": rep,
                "effective_dev": effective_dev or "unknown",
                "effective_via": effective_via,
                "competing_routes": [
                    {"dev": entry.dev, "via": entry.via, "metric": entry.metric, "raw": entry.raw, "source": entry.source}
                    for entry in competing
                ],
                "selected_route": {"dev": iface, "raw": next((entry.raw for entry in route_dev_entries if str(entry.network) == str(network) and entry.dev == iface), "")},
            })
        if effective_dev == iface and ipv4_scope_allowed(network):
            validated.append(network)
        else:
            reason = f"{network} excluded: effective route uses {effective_dev or 'unknown'}"
            if effective_via:
                reason += f" via {effective_via}"
            excluded_networks.append(reason)
    if requested_network is not None and requested_network not in validated:
        raise SystemExit(f"[!] CIDR override {requested_network} is not effectively routed via {iface}.")
    return RouteScope(
        interface=iface,
        requested_network=str(requested_network) if requested_network is not None else "",
        addresses=[],
        candidate_networks=sorted(dict.fromkeys(evaluation_networks), key=lambda n: (int(n.network_address), n.prefixlen)),
        validated_networks=sorted(dict.fromkeys(validated), key=lambda n: (int(n.network_address), n.prefixlen)),
        excluded_networks=excluded_networks,
        overlap_warnings=overlap_warnings,
        route_get_samples=route_get_samples,
        route_text={},
        route_entries=route_dev_entries + route_main_entries,
    )


def get_interface_context(iface: str, outdir: Path, requested_network: ipaddress.IPv4Network | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", iface):
        raise SystemExit("[!] Invalid interface name.")
    if not command_exists("ip"):
        raise SystemExit("[!] Missing required command: ip")
    links = load_json_command(["ip", "-j", "link", "show", "dev", iface])
    if not links:
        raise SystemExit(f"[!] Interface does not exist or cannot be read: {iface}")
    addr_data = load_json_command(["ip", "-j", "-4", "addr", "show", "dev", iface]) or []
    addr_text_record = run_command(["ip", "-4", "addr", "show", "dev", iface], outdir, f"ip_addr_{sanitize(iface)}", timeout=20)
    route_dev_record = run_command(["ip", "-4", "route", "show", "dev", iface], outdir, f"ip_route_{sanitize(iface)}", timeout=20)
    route_main_record = run_command(["ip", "-4", "route", "show", "table", "main"], outdir, "ip_route_main", timeout=20)
    rule_record = run_command(["ip", "-4", "rule", "show"], outdir, "ip_rule", timeout=20)
    route_dev_text = (outdir / route_dev_record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    route_main_text = (outdir / route_main_record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    rule_text = (outdir / rule_record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    write_text_file(outdir / "routes" / f"ip_addr_{sanitize(iface)}.txt", (outdir / addr_text_record["stdout_path"]).read_text(encoding="utf-8", errors="replace"))
    write_text_file(outdir / "routes" / f"ip_route_{sanitize(iface)}.txt", route_dev_text)
    write_text_file(outdir / "routes" / "ip_route_main.txt", route_main_text)
    write_text_file(outdir / "routes" / "ip_rule.txt", rule_text)
    route_dev_entries = parse_ipv4_route_table(route_dev_text, source=f"dev:{iface}", table="dev")
    route_main_entries = parse_ipv4_route_table(route_main_text, source="main", table="main")
    scope = validate_route_scope(iface, addr_data, route_dev_entries, route_main_entries, outdir, requested_network=requested_network)
    addresses = []
    for item in addr_data:
        for addr in item.get("addr_info", []):
            if addr.get("family") != "inet":
                continue
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            if local and prefix is not None:
                addresses.append(f"{local}/{prefix}")
    scope.addresses = sorted(dict.fromkeys(addresses), key=lambda value: ip_sort_key(value.split("/")[0]))
    gateways = sorted({entry.via for entry in route_dev_entries if entry.via and safe_ip(entry.via)}, key=ip_sort_key)
    if not scope.validated_networks:
        raise SystemExit(f"[!] Interface {iface} has no safe local/internal IPv4 scope to scan.")
    scope.route_text = {
        "ip_addr": (outdir / addr_text_record["stdout_path"]).read_text(encoding="utf-8", errors="replace"),
        "ip_route_dev": route_dev_text,
        "ip_route_main": route_main_text,
        "ip_rule": rule_text,
    }
    write_text_file(outdir / "routes" / "route_get_samples.txt", "\n\n".join(
        [
            f"{sample['network']} -> {sample['representative_ip']}\n{sample['stdout'] or sample['stderr']}".strip()
            for sample in scope.route_get_samples
        ]
    ) + "\n")
    write_json_file(outdir / "routes" / "route_overlap_warnings.json", scope.overlap_warnings)
    neigh_record = run_command(["ip", "neigh", "show", "dev", iface], outdir, f"ip_neigh_{sanitize(iface)}", timeout=20)
    return {
        "interface": iface,
        "link": links[0],
        "addresses": scope.addresses,
        "candidate_networks": [str(net) for net in scope.candidate_networks],
        "networks": scope.validated_networks,
        "validated_networks": scope.validated_networks,
        "gateways": gateways,
        "route_text": scope.route_text,
        "route_entries": scope.route_entries,
        "route_get_samples": scope.route_get_samples,
        "route_overlap_warnings": scope.overlap_warnings,
        "route_excluded_networks": scope.excluded_networks,
        "neigh": (outdir / neigh_record["stdout_path"]).read_text(encoding="utf-8", errors="replace"),
        "route_dev_text": route_dev_text,
        "route_main_text": route_main_text,
        "ip_rule_text": rule_text,
        "scan_networks": scope.validated_networks,
    }


def parse_requested_network(value: str) -> ipaddress.IPv4Network | None:
    if not value:
        return None
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise SystemExit(f"[!] Invalid CIDR override: {value}") from exc
    if not isinstance(net, ipaddress.IPv4Network):
        raise SystemExit("[!] CIDR override must be IPv4.")
    if not ipv4_scope_allowed(net):
        raise SystemExit(f"[!] CIDR override is not in allowed private scope: {net}")
    return net


def apply_requested_scope(ctx: dict[str, Any], requested_network: ipaddress.IPv4Network | None) -> dict[str, Any]:
    if requested_network is None:
        return ctx
    networks = [net for net in ctx["networks"] if net == requested_network]
    validated_networks = [net for net in ctx["validated_networks"] if net == requested_network]
    if not networks or not validated_networks:
        raise SystemExit(f"[!] CIDR override {requested_network} is not effectively routed via {ctx['interface']}.")
    ctx = dict(ctx)
    ctx["candidate_networks"] = networks
    ctx["networks"] = validated_networks
    ctx["validated_networks"] = validated_networks
    ctx["scan_networks"] = validated_networks
    ctx["requested_network"] = str(requested_network)
    return ctx


def write_scope(ctx: dict[str, Any], outdir: Path) -> None:
    scope = {
        "interface": ctx["interface"],
        "requested_network": ctx.get("requested_network", ""),
        "addresses": ctx["addresses"],
        "candidate_networks": [str(n) for n in ctx.get("candidate_networks", ctx["networks"])],
        "validated_networks": [str(n) for n in ctx["networks"]],
        "active_networks": [str(n) for n in ctx["networks"] if ipv4_active_allowed(n)],
        "gateways": ctx["gateways"],
        "excluded_routes": ctx.get("route_excluded_networks", []),
        "route_overlap_warnings": ctx.get("route_overlap_warnings", []),
        "route_get_samples": ctx.get("route_get_samples", []),
        "policy": "private interface-derived IPv4 scope only; public/default/loopback/link-local/multicast/broadcast routes excluded; effective kernel route validation required",
    }
    write_json_file(outdir / "scope.json", scope)
    write_text_file(outdir / "scope.txt", "\n".join(scope["active_networks"]) + "\n")


def parse_neighbors(text: str, networks: list[ipaddress.IPv4Network] | None = None) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not safe_ip(parts[0]) or "FAILED" in parts or "INCOMPLETE" in parts:
            continue
        if networks and not ip_in_scope(parts[0], networks):
            continue
        host = hosts.setdefault(parts[0], Host(ip=parts[0]))
        host.sources.add("neighbor-cache")
        if "lladdr" in parts:
            host.mac = parts[parts.index("lladdr") + 1]
    return hosts


def merge_host(hosts: dict[str, Host], incoming: Host) -> Host:
    host = hosts.setdefault(incoming.ip, Host(ip=incoming.ip))
    host.sources.update(incoming.sources)
    host.hostname = host.hostname or incoming.hostname
    host.netbios_name = host.netbios_name or incoming.netbios_name
    host.smb_name = host.smb_name or incoming.smb_name
    host.domain_or_workgroup = host.domain_or_workgroup or incoming.domain_or_workgroup
    host.mdns_name = host.mdns_name or incoming.mdns_name
    host.mac = host.mac or incoming.mac
    host.vendor = host.vendor or incoming.vendor
    host.services.update(incoming.services)
    host.dc_candidate = host.dc_candidate or incoming.dc_candidate
    host.dc_status = host.dc_status if host.dc_status != "none" else incoming.dc_status
    host.dc_confidence = merge_confidence(host.dc_confidence, incoming.dc_confidence)
    host.dc_evidence = list(dict.fromkeys([*host.dc_evidence, *incoming.dc_evidence]))
    if incoming.screenshot_path and not host.screenshot_path:
        host.screenshot_path = incoming.screenshot_path
    return host


def parse_nmap_xml(path: Path) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    if not path.exists() or path.stat().st_size == 0:
        return hosts
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return hosts
    for node in root.findall("host"):
        status = node.find("status")
        if status is not None and status.get("state") not in {"up", None}:
            continue
        ip = ""
        mac = ""
        vendor = ""
        for addr in node.findall("address"):
            if addr.get("addrtype") == "ipv4" and safe_ip(addr.get("addr", "")):
                ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            continue
        host = Host(ip=ip, mac=mac, vendor=vendor)
        host.sources.add("nmap")
        ports = node.find("ports")
        if ports is not None:
            for port_node in ports.findall("port"):
                state = port_node.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port_node.find("service")
                service = Service(port=int(port_node.get("portid", "0")), protocol=port_node.get("protocol", "tcp"))
                if svc is not None:
                    service.name = svc.get("name", "")
                    service.product = svc.get("product", "")
                    service.version = svc.get("version", "")
                    service.extrainfo = svc.get("extrainfo", "")
                host.services[service.port] = service
        add_nmap_host_metadata(host, node)
        hosts[ip] = host
    return hosts


def reverse_dns(ip: str) -> str:
    try:
        previous_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(previous_timeout)


def discover_hosts(ctx: dict[str, Any], outdir: Path, dry_run: bool, performance: dict[str, Any]) -> dict[str, Host]:
    hosts = parse_neighbors(ctx["neigh"], ctx["networks"])
    for gateway in ctx["gateways"]:
        if not ip_in_scope(gateway, ctx["networks"]):
            continue
        host = hosts.setdefault(gateway, Host(ip=gateway))
        host.sources.add("gateway")
    if command_exists("arp"):
        record = run_command(["arp", "-an"], outdir, "arp_cache", timeout=20)
        text = (outdir / record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r"\(([^)]+)\)\s+at\s+([0-9a-fA-F:]{11,17})", text):
            ip, mac = match.groups()
            if safe_ip(ip) and ip_in_scope(ip, ctx["networks"]):
                merge_host(hosts, Host(ip=ip, mac=mac, sources={"arp-cache"}))
    if not dry_run and command_exists("arp-scan") and os.geteuid() == 0 and not is_tunnel_interface(ctx["interface"]):
        for net in sorted([n for n in ctx["networks"] if ipv4_active_allowed(n)], key=network_sort_key):
            name = f"arp_scan_{sanitize(str(net))}"
            record = run_command(["arp-scan", "--interface", ctx["interface"], str(net)], outdir, name, timeout=180)
            text = (outdir / record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                fields = line.split()
                if fields and safe_ip(fields[0]) and ip_in_scope(fields[0], ctx["networks"]):
                    incoming = Host(ip=fields[0], mac=fields[1] if len(fields) > 1 else "", vendor=" ".join(fields[2:]))
                    incoming.sources.add("arp-scan")
                    merge_host(hosts, incoming)
            record_batch(performance, "arp-scan", str(net), record)
    elif command_exists("arp-scan") and is_tunnel_interface(ctx["interface"]):
        append_jsonl(outdir / "events.jsonl", {"time": utc_now(), "source": "arp-scan", "warning": f"skipped on tunnel interface {ctx['interface']}"})
    if not dry_run and command_exists("nmap"):
        targets = [net for net in sorted([n for n in ctx["networks"] if ipv4_active_allowed(n)], key=network_sort_key)]
        for net in targets:
            xml = outdir / f"nmap_discovery_{sanitize(str(net))}.xml"
            cmd = ["nmap", "-sn", "-T3", "--max-retries", "2", "--host-timeout", "30s", "-oX", str(xml), str(net)]
            timeout = max(120, min(7200, net.num_addresses // 8 + 60))
            info(f"Discovery: running bounded nmap ping scan against {net}")
            record = run_command(cmd, outdir, f"nmap_discovery_{sanitize(str(net))}", timeout=timeout)
            record_batch(performance, "discovery", str(net), record)
            for host in parse_nmap_xml(xml).values():
                if ip_in_scope(host.ip, ctx["networks"]):
                    host.sources.add("nmap-ping")
                    merge_host(hosts, host)
        tcp_discovery_scan(hosts, ctx, outdir, dry_run, performance)
    reverse_dns_targets = sorted(hosts.values(), key=lambda item: (-len(item.sources), ip_sort_key(item.ip)))[:min(len(hosts), 120)]
    for host in reverse_dns_targets:
        host.hostname = host.hostname or reverse_dns(host.ip)
    write_live_hosts(hosts, outdir)
    return dict(sorted(hosts.items(), key=lambda item: ip_sort_key(item[0])))


def write_live_hosts(hosts: dict[str, Host], outdir: Path) -> None:
    write_text_file(outdir / "live-hosts.txt", "\n".join(sorted(hosts, key=ip_sort_key)) + "\n")
    write_json_file(outdir / "live-hosts.json", [host_to_dict(h) for h in hosts.values()])


def network_sort_key(network: ipaddress.IPv4Network) -> tuple[int, int, int]:
    return (network.num_addresses, int(network.network_address), network.prefixlen)


def select_network_for_ip(ip: str, networks: list[ipaddress.IPv4Network]) -> ipaddress.IPv4Network | None:
    address = ipaddress.ip_address(ip.split("%", 1)[0])
    matches = [network for network in networks if address in network]
    if not matches:
        return None
    return sorted(matches, key=lambda net: (-net.prefixlen, net.num_addresses, int(net.network_address)))[0]


def group_hosts_by_network(hosts: dict[str, Host], networks: list[ipaddress.IPv4Network]) -> dict[str, list[str]]:
    batches: dict[str, list[str]] = {}
    for host in sorted(hosts.values(), key=lambda item: ip_sort_key(item.ip)):
        network = select_network_for_ip(host.ip, networks)
        key = str(network) if network is not None else "unmatched"
        batches.setdefault(key, []).append(host.ip)
    return batches


def record_batch(performance: dict[str, Any], phase: str, network: str, record: dict[str, Any], host_count: int = 0) -> None:
    performance.setdefault("scan_batches", []).append({
        "phase": phase,
        "network": network,
        "host_count": host_count,
        "timeout_seconds": record.get("timeout_seconds"),
        "exit_code": record.get("exit_code"),
        "timed_out": record.get("timed_out"),
        "duration_seconds": record.get("duration_seconds"),
        "command": record.get("redacted_argv", []),
    })


def quick_scan(hosts: dict[str, Host], ctx: dict[str, Any], outdir: Path, dry_run: bool, performance: dict[str, Any]) -> None:
    if dry_run or not hosts or not command_exists("nmap"):
        return
    networks = [net for net in ctx["networks"] if ipv4_active_allowed(net)]
    batches = group_hosts_by_network(hosts, networks)
    for network in sorted(networks, key=network_sort_key):
        batch_hosts = batches.get(str(network), [])
        if not batch_hosts:
            continue
        target_file = outdir / "performance" / f"fast_targets_{sanitize(str(network))}.txt"
        write_text_file(target_file, "\n".join(batch_hosts) + "\n")
        xml = outdir / f"nmap_fast_{sanitize(str(network))}.xml"
        normal = outdir / f"nmap_fast_{sanitize(str(network))}.nmap"
        grepable = outdir / f"nmap_fast_{sanitize(str(network))}.gnmap"
        cmd = [
            "nmap", "-Pn", "-T3", "--max-retries", "1", "--host-timeout", "90s", "--open",
            "-p", FAST_PORTS, "-oX", str(xml), "-oN", str(normal), "-oG", str(grepable), "-iL", str(target_file),
        ]
        timeout = max(300, min(7200, len(batch_hosts) * 120))
        info(f"Fast scan: scanning {len(batch_hosts)} host(s) in {network}")
        record = run_command(cmd, outdir, f"nmap_fast_{sanitize(str(network))}", timeout=timeout)
        record_batch(performance, "fast-scan", str(network), record, host_count=len(batch_hosts))
        for host in parse_nmap_xml(xml).values():
            host.sources.add("nmap-fast")
            merge_host(hosts, host)
    write_service_map(hosts, outdir)


def tcp_discovery_scan(hosts: dict[str, Host], ctx: dict[str, Any], outdir: Path, dry_run: bool, performance: dict[str, Any]) -> None:
    if dry_run or not command_exists("nmap"):
        return
    networks = [net for net in ctx["networks"] if ipv4_active_allowed(net) and net.num_addresses <= MAX_TCP_DISCOVERY_ADDRESSES]
    for network in sorted(networks, key=network_sort_key):
        xml = outdir / f"nmap_tcp_discovery_{sanitize(str(network))}.xml"
        normal = outdir / f"nmap_tcp_discovery_{sanitize(str(network))}.nmap"
        grepable = outdir / f"nmap_tcp_discovery_{sanitize(str(network))}.gnmap"
        cmd = [
            "nmap", "-Pn", "-n", "-T3", "--max-retries", "1", "--host-timeout", "60s", "--open",
            "-p", DISCOVERY_TCP_PORTS, "-oX", str(xml), "-oN", str(normal), "-oG", str(grepable), str(network),
        ]
        timeout = max(180, min(900, int(network.num_addresses) * 2))
        info(f"Discovery fallback: probing {network} for TCP services")
        record = run_command(cmd, outdir, f"nmap_tcp_discovery_{sanitize(str(network))}", timeout=timeout)
        record_batch(performance, "tcp-discovery", str(network), record, host_count=int(network.num_addresses))
        for host in parse_nmap_xml(xml).values():
            if ip_in_scope(host.ip, ctx["networks"]):
                host.sources.add("nmap-tcp-discovery")
                merge_host(hosts, host)
    write_service_map(hosts, outdir)


def write_service_map(hosts: dict[str, Host], outdir: Path) -> None:
    services = []
    for host in hosts.values():
        for svc in sorted(host.services.values(), key=lambda s: s.port):
            services.append({"host": host.ip, **vars(svc)})
    write_json_file(outdir / "service-map.json", services)


def append_candidate_evidence(candidate: dict[str, Any], evidence: list[str], source_artifacts: list[str]) -> None:
    for item in evidence:
        if item and item not in candidate["evidence"]:
            candidate["evidence"].append(item)
    for item in source_artifacts:
        if item and item not in candidate["source_artifacts"]:
            candidate["source_artifacts"].append(item)


def confidence_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(value, 1)


def merge_confidence(current: str, new: str) -> str:
    return new if confidence_rank(new) > confidence_rank(current) else current


def extract_cves_from_text(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text or "", re.I)))


def parse_dns_server_candidates(text: str) -> list[str]:
    servers = []
    for match in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", text or ""):
        if safe_ip(match) and match not in servers:
            servers.append(match)
    return servers


def parse_dig_srv_output(text: str) -> list[str]:
    targets = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-1].endswith("."):
            target = parts[-1].rstrip(".")
            if target and target not in targets:
                targets.append(target)
    return targets


def infer_domain_name(hosts: dict[str, Host]) -> str:
    candidates: dict[str, int] = {}
    for host in hosts.values():
        for value in [host.domain_or_workgroup, host.hostname, host.mdns_name]:
            normalized = normalize_identity_value(value)
            if not normalized or safe_ip(normalized) or "." not in normalized:
                continue
            candidate = normalized.lower().strip(".")
            if not candidate:
                continue
            candidates[candidate] = candidates.get(candidate, 0) + 1
    if not candidates:
        return "example.local"
    return sorted(candidates.items(), key=lambda item: (-item[1], -len(item[0]), item[0]))[0][0]


def run_optional_command(cmd: list[str], outdir: Path, name: str, timeout: int = 20) -> tuple[str, dict[str, Any]]:
    if not cmd or not command_exists(cmd[0]):
        return "", {"exit_code": None, "timed_out": False}
    record = run_command(cmd, outdir, name, timeout=timeout)
    text = (outdir / record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    return text, record


def load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.exists():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def load_nxc_host_artifacts(nxc_outdir: Path | None) -> dict[str, dict[str, Any]]:
    if nxc_outdir is None or not nxc_outdir.exists():
        return {}
    artifacts: dict[str, dict[str, Any]] = {}
    for rel, bucket in [("jsonl/events.jsonl", "events"), ("jsonl/findings.jsonl", "findings")]:
        for record in load_jsonl_records(nxc_outdir / rel):
            host_value = normalized_findings_host(record.get("host") or record.get("hostname") or record.get("matched-at") or "")
            if not host_value:
                continue
            entry = artifacts.setdefault(host_value, {"events": [], "findings": [], "text": [], "hostnames": [], "domains": []})
            entry[bucket].append(record)
            text_parts = [
                str(record.get("normalized_message", "")),
                str(record.get("raw_redacted_line", "")),
                str(record.get("redacted_evidence", "")),
                str(record.get("message", "")),
            ]
            entry["text"].extend(part for part in text_parts if part)
            hostname = normalize_identity_value(record.get("hostname", "") or (record.get("attributes") or {}).get("hostname", ""))
            domain = normalize_identity_value(record.get("domain", "") or (record.get("attributes") or {}).get("domain", ""))
            if hostname and hostname not in entry["hostnames"]:
                entry["hostnames"].append(hostname)
            if domain and domain not in entry["domains"]:
                entry["domains"].append(domain)
            for field in [record.get("hostname", ""), record.get("domain", "")]:
                value = normalize_identity_value(field)
                if value and value not in entry["text"]:
                    entry["text"].append(value)
    return artifacts


def merge_dc_status(current: str, new: str) -> str:
    order = {"none": 0, "candidate": 1, "confirmed": 2}
    current_value = order.get(current, 0)
    new_value = order.get(new, 0)
    return new if new_value > current_value else current


def update_dc_candidate(
    dc_candidates: dict[str, dict[str, Any]],
    host: Host,
    *,
    confidence: str,
    reason: str,
    evidence: list[str],
    source_artifacts: list[str],
    status: str = "candidate",
    confirmed: bool = False,
) -> dict[str, Any]:
    candidate = dc_candidates.setdefault(host.ip, {
        "ip": host.ip,
        "hostname": host.hostname,
        "netbios_name": host.netbios_name,
        "smb_name": host.smb_name,
        "domain_or_workgroup": host.domain_or_workgroup,
        "evidence": [],
        "confidence": "low",
        "reason": "",
        "confirmed": False,
        "status": "candidate",
        "dc_status": "candidate",
        "source_artifacts": [],
        "open_ports": [],
        "sources": sorted(host.sources),
        "nmap_evidence": [],
        "nxc_evidence": [],
        "dns_evidence": [],
    })
    candidate["hostname"] = candidate["hostname"] or host.hostname
    candidate["netbios_name"] = candidate["netbios_name"] or host.netbios_name
    candidate["smb_name"] = candidate["smb_name"] or host.smb_name
    candidate["domain_or_workgroup"] = candidate["domain_or_workgroup"] or host.domain_or_workgroup
    candidate["confidence"] = merge_confidence(str(candidate.get("confidence", "low")), confidence)
    candidate["reason"] = reason if not candidate.get("reason") else candidate["reason"]
    candidate["status"] = merge_dc_status(str(candidate.get("status", "candidate")), "confirmed" if confirmed or status == "confirmed" else status)
    candidate["dc_status"] = candidate["status"]
    candidate["confirmed"] = bool(candidate.get("confirmed")) or confirmed or candidate["status"] == "confirmed"
    candidate["sources"] = sorted(set(candidate.get("sources", [])) | set(host.sources))
    candidate["open_ports"] = sorted(set(candidate.get("open_ports", [])) | set(host.services))
    append_candidate_evidence(candidate, evidence, source_artifacts)
    return candidate


def host_dc_signals(host: Host, nxc_artifacts: dict[str, Any] | None = None) -> dict[str, Any]:
    ports = set(host.services)
    service_text = " ".join(
        " ".join(filter(None, [svc.name, svc.product, svc.version, svc.extrainfo])).lower()
        for svc in host.services.values()
    )
    host_text = " ".join(
        filter(
            None,
            [
                host.hostname,
                host.netbios_name,
                host.smb_name,
                host.domain_or_workgroup,
                host.mdns_name,
            ],
        )
    ).lower()
    nxc_text = " ".join(str(item) for item in (nxc_artifacts or {}).get("text", [])).lower()
    nxc_hostnames = [normalize_identity_value(item) for item in (nxc_artifacts or {}).get("hostnames", []) if normalize_identity_value(item)]
    nxc_domains = [normalize_identity_value(item) for item in (nxc_artifacts or {}).get("domains", []) if normalize_identity_value(item)]
    explicit_terms = ("active directory", "domain controller", "microsoft dns", "global catalog")
    nxc_explicit = any(term in nxc_text for term in explicit_terms)
    nmap_explicit = any(term in service_text for term in explicit_terms + ("kerberos", "ldap", "microsoft dns"))
    ad_port_mix = 88 in ports and 445 in ports and bool(ports & {389, 636, 3268, 3269})
    identity_port_mix = {53, 88, 389, 445}.issubset(ports) or len(ports & {88, 389, 445, 636, 3268, 3269}) >= 4
    hostname_hint = bool(host_text and re.search(r"(^|[-_.])(dc|ad|ldap|domain)([-_.]|$)", host_text, re.I))
    nxc_name_hint = any(re.search(r"(^|[-_.])(dc|ad|ldap|domain)([-_.]|$)", value, re.I) for value in [*nxc_hostnames, *nxc_domains])
    srv_hits = list((nxc_artifacts or {}).get("dns_evidence", []))
    signals = {
        "ports": sorted(ports),
        "service_text": service_text,
        "nxc_text": nxc_text,
        "ad_port_mix": ad_port_mix,
        "identity_port_mix": identity_port_mix,
        "nmap_explicit": nmap_explicit,
        "nxc_explicit": nxc_explicit,
        "hostname_hint": hostname_hint,
        "nxc_name_hint": nxc_name_hint,
        "srv_hits": srv_hits,
        "evidence": [],
    }
    if srv_hits:
        signals["evidence"].append("DNS SRV points to this host: " + ", ".join(sorted(dict.fromkeys(map(str, srv_hits)))))
    if ad_port_mix:
        signals["evidence"].append("Kerberos + LDAP/LDAPS + SMB port mix")
    elif identity_port_mix:
        signals["evidence"].append("Identity services exposed: " + ", ".join(map(str, sorted(ports & {53, 88, 389, 445, 464, 636, 3268, 3269}))))
    if nmap_explicit:
        signals["evidence"].append("Nmap service detection suggests Active Directory / directory services")
    if nxc_explicit:
        signals["evidence"].append("Host-specific NXC output references Active Directory / domain controller behavior")
    if hostname_hint:
        signals["evidence"].append(f"Hostname or NetBIOS name hints at directory infrastructure: {host.hostname or host.netbios_name or host.smb_name}")
    if nxc_name_hint:
        signals["evidence"].append("NXC name/domain hints align with directory infrastructure")
    return signals


def classify_dc_signals(signals: dict[str, Any]) -> tuple[str, str, bool, str]:
    srv_hits = [str(item) for item in signals.get("srv_hits", []) if str(item).strip()]
    ad_port_mix = bool(signals.get("ad_port_mix"))
    identity_port_mix = bool(signals.get("identity_port_mix"))
    nmap_explicit = bool(signals.get("nmap_explicit"))
    nxc_explicit = bool(signals.get("nxc_explicit"))
    hostname_hint = bool(signals.get("hostname_hint"))
    nxc_name_hint = bool(signals.get("nxc_name_hint"))
    evidence = list(dict.fromkeys(str(item) for item in signals.get("evidence", []) if str(item).strip()))
    if srv_hits and (ad_port_mix or nmap_explicit or nxc_explicit):
        reason = "DNS SRV records resolve this host and the service mix matches directory infrastructure."
        return "confirmed", "high", True, reason
    if (nmap_explicit or nxc_explicit) and ad_port_mix:
        reason = "Directory-service evidence and the Kerberos/LDAP/SMB port mix indicate a domain controller."
        return "confirmed", "high", True, reason
    if srv_hits and (identity_port_mix or hostname_hint or nxc_name_hint):
        reason = "DNS SRV records point to this host, but supporting evidence is not yet strong enough to confirm it."
        return "candidate", "medium", False, reason
    if (nmap_explicit or nxc_explicit) and identity_port_mix:
        reason = "Directory-service evidence is present, but more host-specific validation is needed."
        return "candidate", "medium", False, reason
    if ad_port_mix and (hostname_hint or nxc_name_hint):
        reason = "Directory-style ports and name hints suggest a possible domain controller."
        return "candidate", "medium", False, reason
    if identity_port_mix and (hostname_hint or nxc_name_hint):
        reason = "Identity-related ports and name hints suggest a possible domain controller."
        return "candidate", "medium", False, reason
    return "none", "low", False, ""


def discover_domain_controllers(
    ctx: dict[str, Any],
    hosts: dict[str, Host],
    outdir: Path,
    performance: dict[str, Any],
    dry_run: bool,
    nxc_outdir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    domain_dir = outdir / "domain"
    domain_dir.mkdir(parents=True, exist_ok=True)
    dc_candidates: dict[str, dict[str, Any]] = {}
    domain_name = infer_domain_name(hosts)
    dns_config_parts: list[str] = []
    if command_exists("resolvectl"):
        for cmd_name, cmd in [
            ("dns", ["resolvectl", "dns"]),
            ("domain", ["resolvectl", "domain"]),
            ("status", ["resolvectl", "status"]),
        ]:
            text, record = run_optional_command(cmd, outdir, f"resolvectl_{cmd_name}", timeout=20)
            if text:
                dns_config_parts.append(f"## resolvectl {cmd_name}\n{text.strip()}")
            performance.setdefault("commands", []).append(record)
    dns_servers = parse_dns_server_candidates("\n".join(dns_config_parts))
    if not dns_servers and command_exists("dig"):
        dns_servers = []
    if dns_config_parts:
        write_text_file(domain_dir / "dns_config.txt", "\n\n".join(dns_config_parts) + "\n")
    else:
        write_text_file(domain_dir / "dns_config.txt", "resolvectl not available or returned no configuration.\n")
    srv_targets: dict[str, list[str]] = {}
    srv_queries_by_ip: dict[str, list[str]] = {}
    srv_artifacts_by_ip: dict[str, list[str]] = {}
    if not dry_run and command_exists("dig"):
        for label in ("ldap", "kerberos"):
            query = DC_SRV_RECORDS[0].format(domain=domain_name) if label == "ldap" else DC_SRV_RECORDS[1].format(domain=domain_name)
            query_name = f"{sanitize(domain_name)}_srv_{label}"
            query_cmd = ["dig", "+short", query, "SRV"]
            if dns_servers:
                query_cmd = ["dig", "+short", f"@{dns_servers[0]}", query, "SRV"]
            text, record = run_optional_command(query_cmd, outdir, query_name, timeout=25)
            write_text_file(domain_dir / f"{query_name}.txt", text or "")
            performance.setdefault("commands", []).append(record)
            srv_targets[label] = parse_dig_srv_output(text)
            artifact_paths = [f"domain/{query_name}.txt"]
            resolved_hosts: list[str] = []
            for target in srv_targets[label]:
                resolve_cmd = ["dig", "+short", target, "A"]
                if dns_servers:
                    resolve_cmd = ["dig", "+short", f"@{dns_servers[0]}", target, "A"]
                resolved_text, resolve_record = run_optional_command(resolve_cmd, outdir, f"resolve_{sanitize(target)}", timeout=20)
                performance.setdefault("commands", []).append(resolve_record)
                write_text_file(domain_dir / f"resolve_{sanitize(target)}.txt", resolved_text or "")
                artifact_paths.append(f"domain/resolve_{sanitize(target)}.txt")
                for ip in [line.strip() for line in resolved_text.splitlines() if safe_ip(line.strip())]:
                    if not ip_in_scope(ip, ctx["networks"]):
                        continue
                    if ip not in resolved_hosts:
                        resolved_hosts.append(ip)
                    host = hosts.setdefault(ip, Host(ip=ip))
                    host.sources.add("dns-srv")
                    srv_queries_by_ip.setdefault(ip, []).append(query)
                    srv_artifacts_by_ip.setdefault(ip, []).extend(artifact_paths)
            for ip in resolved_hosts:
                host = hosts[ip]
                host.sources.add("dns-srv")
    elif not dry_run and command_exists("nslookup"):
        for label in ("ldap", "kerberos"):
            query = DC_SRV_RECORDS[0].format(domain=domain_name) if label == "ldap" else DC_SRV_RECORDS[1].format(domain=domain_name)
            query_name = f"{sanitize(domain_name)}_srv_{label}"
            nslookup_cmd = ["nslookup", "-type=SRV", query]
            if dns_servers:
                nslookup_cmd = ["nslookup", "-type=SRV", query, dns_servers[0]]
            text, record = run_optional_command(nslookup_cmd, outdir, query_name, timeout=25)
            performance.setdefault("commands", []).append(record)
            write_text_file(domain_dir / f"{query_name}.txt", text or "")
            srv_targets[label] = parse_dig_srv_output(text)
            artifact_paths = [f"domain/{query_name}.txt"]
            for target in srv_targets[label]:
                resolve_cmd = ["nslookup", target]
                if dns_servers:
                    resolve_cmd = ["nslookup", target, dns_servers[0]]
                resolved_text, resolve_record = run_optional_command(resolve_cmd, outdir, f"resolve_{sanitize(target)}", timeout=20)
                performance.setdefault("commands", []).append(resolve_record)
                write_text_file(domain_dir / f"resolve_{sanitize(target)}.txt", resolved_text or "")
                for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", resolved_text):
                    if safe_ip(ip) and ip_in_scope(ip, ctx["networks"]) and ip not in hosts:
                        hosts[ip] = Host(ip=ip, sources={"dns-srv"})
                    if safe_ip(ip) and ip_in_scope(ip, ctx["networks"]):
                        host = hosts[ip]
                        host.sources.add("dns-srv")
                        srv_queries_by_ip.setdefault(ip, []).append(query)
                        srv_artifacts_by_ip.setdefault(ip, []).extend([f"domain/{query_name}.txt", f"domain/resolve_{sanitize(target)}.txt"])
    nxc_artifacts = load_nxc_host_artifacts(nxc_outdir)
    for host in sorted(hosts.values(), key=lambda item: ip_sort_key(item.ip)):
        host_artifact = dict(nxc_artifacts.get(host.ip, {}))
        host_artifact["dns_evidence"] = srv_queries_by_ip.get(host.ip, [])
        signals = host_dc_signals(host, host_artifact)
        status, confidence, confirmed, reason = classify_dc_signals(signals)
        if status == "none":
            continue
        if host_artifact.get("text"):
            apply_identity_hints(host, " ".join(host_artifact.get("text", [])), source="nxc")
        host.dc_candidate = True
        host.dc_status = merge_dc_status(host.dc_status, status)
        host.dc_confidence = merge_confidence(host.dc_confidence, confidence)
        host.dc_evidence.extend(signals.get("evidence", []))
        candidate = update_dc_candidate(
            dc_candidates,
            host,
            confidence=confidence,
            reason=reason,
            evidence=signals.get("evidence", []) or [reason],
            source_artifacts=sorted(dict.fromkeys([*srv_artifacts_by_ip.get(host.ip, []), "nxc/jsonl/events.jsonl", "nxc/jsonl/findings.jsonl", "nxc/reports/markdown-summary.md"])),
            status=status,
            confirmed=confirmed,
        )
        candidate["domain_name"] = candidate.get("domain_name") or domain_name
        candidate["dns_evidence"].extend(srv_queries_by_ip.get(host.ip, []))
        candidate["nxc_evidence"].extend(signals.get("evidence", []))
        candidate["netbios_name"] = candidate["netbios_name"] or host.netbios_name
        candidate["smb_name"] = candidate["smb_name"] or host.smb_name
        candidate["domain_or_workgroup"] = candidate["domain_or_workgroup"] or host.domain_or_workgroup
    if nxc_outdir is not None and nxc_outdir.exists():
        nxc_text_parts = []
        for rel in ["jsonl/events.jsonl", "jsonl/findings.jsonl", "reports/markdown-summary.md", "json/summary.json"]:
            path = nxc_outdir / rel
            if path.exists():
                nxc_text_parts.append(f"## {rel}\n{path.read_text(encoding='utf-8', errors='replace')}")
        nxc_text = "\n\n".join(nxc_text_parts)
        if nxc_text:
            write_text_file(domain_dir / "nxc_evidence.txt", nxc_text + "\n")
    ordered = sorted(
        dc_candidates.values(),
        key=lambda item: (-confidence_rank(str(item.get("confidence", "low"))), -len(item.get("evidence", [])), item["ip"]),
    )
    write_json_file(domain_dir / "dc_candidates.json", ordered)
    lines = ["# Domain Controller Candidates", ""]
    if not ordered:
        lines.append("No domain controllers were discovered or strongly inferred.")
    for item in ordered:
        lines.append(f"- {item['ip']} {item.get('hostname') or ''}".rstrip())
        lines.append(f"  - confidence: {item.get('confidence', 'low')}")
        lines.append(f"  - confirmed: {'yes' if item.get('confirmed') else 'no'}")
        lines.append(f"  - reason: {item.get('reason')}")
        lines.append(f"  - open ports: {', '.join(map(str, item.get('open_ports', []))) or 'none'}")
        lines.append(f"  - evidence: {'; '.join(item.get('evidence', [])) or 'none'}")
        lines.append(f"  - source artifacts: {', '.join(item.get('source_artifacts', [])) or 'none'}")
    write_text_file(domain_dir / "dc_candidates.md", "\n".join(lines) + "\n")
    return {item["ip"]: item for item in ordered}


def add_reason(host: Host, score: int, reason: str) -> None:
    host.score += score
    if reason not in host.ranking_reasons:
        host.ranking_reasons.append(reason)


def classify_and_rank(hosts: dict[str, Host], gateways: list[str], dc_candidates: dict[str, dict[str, Any]] | None = None) -> list[Host]:
    for host in hosts.values():
        host.score = 0
        host.ranking_reasons = []
        ports = set(host.services)
        if dc_candidates and host.ip in dc_candidates:
            candidate = dc_candidates[host.ip]
            host.dc_candidate = True
            host.dc_status = str(candidate.get("status", "candidate") or "candidate")
            host.dc_confidence = str(candidate.get("confidence", "medium"))
            host.dc_evidence = list(dict.fromkeys(host.dc_evidence + candidate.get("evidence", [])))
            dc_domain = normalize_identity_value(candidate.get("domain_name", "")) or (host.domain_or_workgroup if host.domain_or_workgroup and "." in host.domain_or_workgroup else "")
            if dc_domain:
                dc_reason = f"Domain controller {'confirmed' if host.dc_status == 'confirmed' else 'candidate'} for {dc_domain} ({host.dc_confidence})"
            else:
                dc_reason = f"Domain controller {'confirmed' if host.dc_status == 'confirmed' else 'candidate'} ({host.dc_confidence})"
            add_reason(host, 70 if host.dc_confidence == "high" else 55, dc_reason)
            add_reason(host, 20, "DC evidence: " + "; ".join(candidate.get("evidence", [])[:3]))
            host.role_guess, host.role_confidence = ("domain controller" if host.dc_status == "confirmed" else "domain controller candidate"), host.dc_confidence
        if host.ip in gateways:
            add_reason(host, 45, "Likely gateway/router/firewall: interface route points to this host")
            host.role_guess, host.role_confidence = "gateway/router/firewall", "high"
        if host.ip == FRITZBOX_IP:
            add_reason(host, 60, "Likely FritzBox/router candidate at 192.168.100.1")
            host.role_guess, host.role_confidence = "FritzBox/router candidate", "high"
        if len({53, 88, 389, 445} & ports) >= 3:
            add_reason(host, 45, "Likely identity infrastructure: DNS/Kerberos/LDAP/SMB indicators")
            host.role_guess, host.role_confidence = "identity infrastructure", "medium"
        if ports & {445, 2049, 111}:
            add_reason(host, 22, "File/storage protocol exposed")
        if ports & {3389, 5985, 5986, 22, 5900}:
            add_reason(host, 22, "Remote administration protocol exposed")
        if ports & WEB_PORTS:
            add_reason(host, 18, "HTTP/HTTPS or web management service exposed")
        if ports & {1433, 1521, 3306, 5432, 6379, 9200, 9300}:
            add_reason(host, 25, "Database or data service exposed")
        if ports & {21, 23}:
            add_reason(host, 18, "Legacy cleartext service exposed")
        high = ports & HIGH_IMPACT_PORTS
        if high:
            add_reason(host, min(35, len(high) * 5), "High-impact ports: " + ", ".join(map(str, sorted(high))))
        if len(ports) >= 8:
            add_reason(host, 20, f"Broad service exposure: {len(ports)} open TCP ports")
        elif len(ports) >= 4:
            add_reason(host, 10, f"Moderate service exposure: {len(ports)} open TCP ports")
        if not host.ranking_reasons:
            add_reason(host, 1, "Live host discovered with no high-impact service evidence")
            host.role_guess = "unknown"
    return sorted(hosts.values(), key=lambda h: (-h.score, -len(h.services), ip_sort_key(h.ip)))[:MAX_TOP_HOSTS]


def codex_select_top_hosts(hosts: dict[str, Host], deterministic: list[Host], outdir: Path, model: str, reasoning: str, dc_candidates: dict[str, dict[str, Any]] | None = None) -> list[Host]:
    prompts = outdir / "codex"
    prompts.mkdir(exist_ok=True)
    evidence = {
        "instruction": "Select up to 10 highest-priority local internal hosts for deeper safe assessment. Do not invent roles; mark inferred roles with confidence.",
        "reasoning_profile": reasoning,
        "priority_rules": ["prioritize reachable 192.168.100.1 as likely FritzBox/router", "gateways", "DNS/DHCP/identity", "NAS/storage", "admin protocols", "databases", "web admin", "domain controllers only when strong host-specific evidence exists"],
        "hosts": [host_to_dict(h) for h in deterministic],
    }
    prompt_path = prompts / "top-host-selection-prompt.json"
    response_path = prompts / "top-host-selection-response.txt"
    prompt_path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    if not model or not command_exists("codex"):
        response_path.write_text("Codex unavailable; deterministic prioritization used.\n", encoding="utf-8")
        return deterministic
    schema = prompts / "top-host-selection-schema.json"
    schema.write_text(json.dumps({
        "type": "object",
        "additionalProperties": False,
        "properties": {"hosts": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"ip": {"type": "string"}, "rationale": {"type": "string"}}, "required": ["ip", "rationale"]}}},
        "required": ["hosts"],
    }, indent=2), encoding="utf-8")
    prompt = "Return JSON only matching the provided schema.\n" + prompt_path.read_text(encoding="utf-8")
    cmd = ["codex", "exec", "--model", model, "--output-schema", str(schema), "--output-last-message", str(response_path), prompt]
    record = run_command(cmd, outdir, "codex_top_hosts", timeout=240)
    if record["exit_code"] != 0 or not response_path.exists():
        warn("Codex top-host selection failed; using deterministic prioritization.")
        return ensure_required_top_hosts(deterministic, hosts, dc_candidates)
    try:
        data = json.loads(response_path.read_text(encoding="utf-8"))
        selected = []
        for item in data.get("hosts", []):
            ip = str(item.get("ip", ""))
            if ip in hosts and ip not in [h.ip for h in selected]:
                selected.append(hosts[ip])
        return ensure_required_top_hosts(selected or deterministic, hosts, dc_candidates)
    except Exception as exc:
        append_jsonl(outdir / "events.jsonl", {"time": utc_now(), "source": "codex", "error": str(exc)})
        return ensure_required_top_hosts(deterministic, hosts, dc_candidates)


def ensure_required_top_hosts(selected: list[Host], hosts: dict[str, Host], dc_candidates: dict[str, dict[str, Any]] | None = None) -> list[Host]:
    required = []
    if dc_candidates:
        for ip in dc_candidates:
            if ip in hosts:
                required.append(hosts[ip])
    if FRITZBOX_IP in hosts:
        required.append(hosts[FRITZBOX_IP])
    ordered: list[Host] = []
    seen = set()
    for host in [*required, *selected]:
        if host.ip in seen:
            continue
        ordered.append(host)
        seen.add(host.ip)
    ordered = sorted(ordered, key=lambda h: (-h.score, -len(h.services), ip_sort_key(h.ip)))
    if dc_candidates:
        dc_hosts = [hosts[ip] for ip in dc_candidates if ip in hosts]
        non_dc = [host for host in ordered if host.ip not in dc_candidates]
        ordered = sorted(dc_hosts, key=lambda h: (-h.score, ip_sort_key(h.ip))) + non_dc
    if FRITZBOX_IP in hosts:
        fritz = hosts[FRITZBOX_IP]
        without = [host for host in ordered if host.ip != FRITZBOX_IP]
        ordered = [fritz] + without if fritz in ordered else [fritz, *without]
    final: list[Host] = []
    seen.clear()
    for host in ordered:
        if host.ip in seen:
            continue
        final.append(host)
        seen.add(host.ip)
        if len(final) >= MAX_TOP_HOSTS:
            break
    if dc_candidates:
        for ip in dc_candidates:
            if ip in seen:
                continue
            if ip in hosts:
                final.insert(0, hosts[ip])
                seen.add(ip)
        final = final[:MAX_TOP_HOSTS]
    return final


def write_top_hosts(top_hosts: list[Host], outdir: Path, ctx: dict[str, Any], dc_candidates: dict[str, dict[str, Any]] | None = None) -> None:
    status = "not_in_scope"
    if any(ipaddress.ip_address(FRITZBOX_IP) in net for net in ctx["networks"]):
        status = "unreachable_or_not_discovered"
    if any(h.ip == FRITZBOX_IP for h in top_hosts):
        status = "reachable_and_prioritized"
    data = {
        "fritzbox_status": status,
        "domain_controller_candidates": [dc_candidates[ip] for ip in dc_candidates] if dc_candidates else [],
        "hosts": [host_to_dict(h) for h in top_hosts],
    }
    write_json_file(outdir / "top-hosts.json", data)
    lines = [f"# Top Hosts", "", f"192.168.100.1 status: {status}", ""]
    if dc_candidates:
        lines.append("## Domain Controller Candidates")
        for item in dc_candidates.values():
            lines.append(f"- {item['ip']} {item.get('hostname') or ''}".rstrip())
            lines.append(f"  - status: {item.get('status', 'candidate')}")
            lines.append(f"  - confidence: {item.get('confidence')}")
            lines.append(f"  - confirmed: {'yes' if item.get('confirmed') else 'no'}")
            lines.append(f"  - evidence: {'; '.join(item.get('evidence', [])) or 'none'}")
        lines.append("")
    for idx, host in enumerate(top_hosts, 1):
        lines.append(f"{idx}. {host.ip} score={host.score} role={host.role_guess or 'unknown'} confidence={host.role_confidence}")
        for reason in host.ranking_reasons:
            lines.append(f"   - {reason}")
    write_text_file(outdir / "top-hosts.md", "\n".join(lines) + "\n")


def deep_scan(top_hosts: list[Host], hosts: dict[str, Host], outdir: Path, dry_run: bool) -> None:
    if dry_run or not top_hosts or not command_exists("nmap"):
        return
    safe_scripts = ",".join([
        "banner",
        "http-title",
        "http-headers",
        "ssl-cert",
        "ssl-enum-ciphers",
        "ssh2-enum-algos",
        "smb-protocols",
        "smb-security-mode",
        "smb-os-discovery",
        "dns-nsid",
        "ftp-anon",
        "rdp-enum-encryption",
        "vnc-info",
        "nfs-showmount",
    ])
    for host in top_hosts:
        ports = sorted(host.services) or []
        port_arg = ",".join(map(str, ports)) if ports else FAST_PORTS
        xml = outdir / f"nmap_deep_{sanitize(host.ip)}.xml"
        cmd = [
            "nmap", "-Pn", "-sV", "--version-light", "-T3", "--max-retries", "2",
            "--host-timeout", "8m", "--script-timeout", "20s", "--script", safe_scripts,
            "--open", "-p", port_arg, "-oX", str(xml), host.ip,
        ]
        info(f"Deep scan: {host.ip}")
        run_command(cmd, outdir, f"nmap_deep_{sanitize(host.ip)}", timeout=540)
        parsed = parse_nmap_xml(xml)
        if host.ip in parsed:
            parsed[host.ip].sources.add("nmap-deep")
            merge_host(hosts, parsed[host.ip]).deep_scanned = True
        host.deep_scanned = True
    write_service_map(hosts, outdir)


def service_url(ip: str, port: int) -> str:
    scheme = "https" if port in {443, 8443, 9443} else "http"
    return f"{scheme}://{ip}/" if port in {80, 443} else f"{scheme}://{ip}:{port}/"


def run_nuclei(top_hosts: list[Host], outdir: Path, dry_run: bool) -> list[dict[str, Any]]:
    urls = [service_url(h.ip, p) for h in top_hosts for p in sorted(set(h.services) & WEB_PORTS)]
    if not urls:
        (outdir / "nuclei_targets.txt").write_text("No HTTP/HTTPS targets selected.\n", encoding="utf-8")
        (outdir / "nuclei_safe.jsonl").touch()
        return []
    if dry_run or not command_exists("nuclei"):
        (outdir / "nuclei_targets.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
        (outdir / "nuclei_safe.jsonl").touch()
        return []
    target_file = outdir / "nuclei_targets.txt"
    output = outdir / "nuclei_safe.jsonl"
    target_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    cmd = ["nuclei", "-l", str(target_file), "-tags", SAFE_NUCLEI_TAGS, "-severity", SAFE_NUCLEI_SEVERITIES, "-exclude-tags", "bruteforce,fuzz,dos,intrusive,exploit", "-rl", "20", "-c", "10", "-timeout", "7", "-retries", "1", "-jsonl", "-o", str(output), "-silent"]
    info("Nuclei: running safe local web checks")
    run_command(cmd, outdir, "nuclei_safe", timeout=min(900, max(180, len(urls) * 30)))
    findings = []
    if output.exists():
        for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                append_jsonl(outdir / "events.jsonl", {"time": utc_now(), "source": "nuclei", "parse_error": line[:300]})
    return findings


def choose_web_service(host: Host) -> tuple[int, str] | tuple[None, None]:
    for port in sorted(set(host.services) & WEB_PORTS, key=lambda p: (0 if p in {443, 8443, 9443} else 1, p)):
        return port, service_url(host.ip, port)
    return None, None


def capture_web_screenshots(top_hosts: list[Host], outdir: Path, dry_run: bool, performance: dict[str, Any]) -> dict[str, Any]:
    screenshots_dir = outdir / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    if dry_run:
        return {"available": False, "targets": []}
    browser = next((name for name in SUPPORTED_SCREENSHOT_BROWSERS if command_exists(name)), "")
    if not browser:
        return {"available": False, "targets": []}
    for host in top_hosts:
        port, url = choose_web_service(host)
        if port is None or url is None:
            continue
        image_path = screenshots_dir / f"{sanitize(host.ip)}.png"
        if browser.startswith("chromium") or browser.startswith("google-chrome") or browser == "msedge":
            cmd = [
                browser,
                "--headless",
                "--disable-gpu",
                "--hide-scrollbars",
                "--ignore-certificate-errors",
                "--no-sandbox",
                f"--screenshot={image_path}",
                "--window-size=1440,960",
                url,
            ]
        else:
            continue
        record = run_command(cmd, outdir, f"screenshot_{sanitize(host.ip)}", timeout=90)
        performance.setdefault("screenshots", []).append({
            "host": host.ip,
            "port": port,
            "url": url,
            "path": str(image_path.relative_to(outdir)),
            "exit_code": record["exit_code"],
            "timed_out": record["timed_out"],
        })
        if image_path.exists():
            host.screenshot_path = str(image_path.relative_to(outdir))
            manifest.append({"host": host.ip, "port": port, "url": url, "path": host.screenshot_path, "exit_code": record["exit_code"]})
    write_json_file(screenshots_dir / "manifest.json", manifest)
    return {"available": True, "targets": manifest, "browser": browser}


def aggregate_performance(outdir: Path, performance: dict[str, Any]) -> dict[str, Any]:
    commands_path = outdir / "commands.jsonl"
    records = []
    if commands_path.exists():
        for line in commands_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    phase_map = {
        "route_validation": [],
        "discovery": [],
        "fast_scan": [],
        "codex": [],
        "deep_scan": [],
        "nuclei": [],
        "nxc": [],
        "screenshots": [],
        "bootstrap": [],
        "other": [],
    }
    for record in records:
        name = str(record.get("name", ""))
        duration = float(record.get("duration_seconds", 0.0) or 0.0)
        timed_out = bool(record.get("timed_out"))
        if name.startswith("version_"):
            phase = "bootstrap"
        elif name.startswith("ip_addr_") or name.startswith("ip_route_") or name == "ip_rule" or name.startswith("ip_neigh_") or name.startswith("route_get_"):
            phase = "route_validation"
        elif name.startswith("arp_") or name.startswith("nmap_discovery") or name.startswith("nmap_tcp_discovery"):
            phase = "discovery"
        elif name.startswith("nmap_fast"):
            phase = "fast_scan"
        elif name == "codex_top_hosts":
            phase = "codex"
        elif name.startswith("nmap_deep_"):
            phase = "deep_scan"
        elif name == "nuclei_safe":
            phase = "nuclei"
        elif name == "nxc_phase":
            phase = "nxc"
        elif name.startswith("screenshot_"):
            phase = "screenshots"
        else:
            phase = "other"
        phase_map.setdefault(phase, []).append({
            "name": name,
            "duration_seconds": duration,
            "timeout_seconds": record.get("timeout_seconds"),
            "exit_code": record.get("exit_code"),
            "timed_out": timed_out,
        })
    phase_durations = {
        phase: {
            "duration_seconds": round(sum(item["duration_seconds"] for item in items), 3),
            "commands": [item["name"] for item in items],
            "timeout_count": sum(1 for item in items if item["timed_out"]),
        }
        for phase, items in phase_map.items()
    }
    timeouts = [rec for rec in records if rec.get("timed_out") or rec.get("exit_code") == 124]
    slow_hosts = [
        {
            "name": rec.get("name"),
            "duration_seconds": rec.get("duration_seconds"),
            "timeout_seconds": rec.get("timeout_seconds"),
            "exit_code": rec.get("exit_code"),
        }
        for rec in sorted((r for r in records if str(r.get("name", "")).startswith("nmap_deep_")), key=lambda item: float(item.get("duration_seconds", 0.0) or 0.0), reverse=True)
    ]
    summary = {
        "phase_durations": phase_durations,
        "timeouts": timeouts,
        "slow_hosts": slow_hosts,
        "scan_batches": performance.get("scan_batches", []),
        "screenshots": performance.get("screenshots", []),
    }
    performance_dir = outdir / "performance"
    performance_dir.mkdir(parents=True, exist_ok=True)
    write_json_file(performance_dir / "phase_durations.json", phase_durations)
    write_json_file(performance_dir / "timeouts.json", timeouts)
    write_json_file(performance_dir / "slow_hosts.json", slow_hosts)
    write_json_file(performance_dir / "scan_batches.json", performance.get("scan_batches", []))
    return summary


def run_nxc(top_hosts: list[Host], outdir: Path, dry_run: bool) -> dict[str, Any]:
    nxc_out = outdir / "nxc"
    nxc_out.mkdir(exist_ok=True)
    target_file = nxc_out / "top-targets.txt"
    target_file.write_text("\n".join(h.ip for h in top_hosts) + "\n", encoding="utf-8")
    protocols = sorted(protocols_for_hosts(top_hosts))
    summary = {"available": command_exists("nxc"), "selected_protocols": protocols, "ran": False, "out": str(nxc_out.relative_to(outdir))}
    if dry_run or not protocols or not command_exists("nxc"):
        for rel in ["meta/help", "meta/modules", "meta/module_options", "targets", "logs/raw", "logs/nxc", "logs/stderr", "jsonl", "json", "db_exports/raw", "db_exports/json", "native_artifacts/spider_plus", "native_artifacts/bloodhound", "native_artifacts/screenshots", "native_artifacts/other", "reports"]:
            (nxc_out / rel).mkdir(parents=True, exist_ok=True)
        for name in ["commands.jsonl", "events.jsonl", "findings.jsonl"]:
            (nxc_out / "jsonl" / name).touch()
        for name in ["hosts", "services", "auth_successes", "admin_rights", "shares", "nfs_exports", "mssql", "ldap"]:
            (nxc_out / "json" / f"{name}.json").write_text("[]\n", encoding="utf-8")
        (nxc_out / "json" / "modules.json").write_text("{}\n", encoding="utf-8")
        (nxc_out / "reports" / "markdown-summary.md").write_text("# NXC Summary\n\nNo protocol-specific NXC targets were selected.\n", encoding="utf-8")
        (nxc_out / "json" / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary
    cmd = [
        sys.executable, str(ROOT / "tools" / "nxc_phase.py"),
        "--targets", str(target_file), "--service-map", str(outdir / "service-map.json"), "--out", str(nxc_out),
        "--run-id", outdir.name, "--workspace", ROOT.name, "--protocols", ",".join(protocols), "--mode", "recon",
        "--threads", "4", "--timeout", "8", "--jitter", "0", "--dns-timeout", "5", "--authorized", "--redact-secrets", "--audit-mode", "--resume",
    ]
    info("NXC: running safe protocol recon for observed services")
    record = run_command(cmd, outdir, "nxc_phase", timeout=max(300, len(protocols) * len(top_hosts) * 45))
    summary["ran"] = True
    summary["exit_code"] = record.get("exit_code")
    summary["timed_out"] = record.get("timed_out", False)
    child_summary = nxc_out / "json" / "summary.json"
    if child_summary.exists():
        try:
            summary.update(json.loads(child_summary.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            summary["parse_status"] = "summary_json_invalid"
    elif record.get("exit_code") not in {0, None}:
        summary["parse_status"] = "summary_missing"
    return summary


def protocols_for_hosts(hosts: list[Host]) -> set[str]:
    protocols = set()
    for host in hosts:
        ports = set(host.services)
        if ports & {445, 139}: protocols.add("smb")
        if ports & {389, 636, 3268, 3269}: protocols.add("ldap")
        if ports & {5985, 5986}: protocols.add("winrm")
        if {135, 445}.issubset(ports): protocols.add("wmi")
        if ports & {1433}: protocols.add("mssql")
        if ports & {22}: protocols.add("ssh")
        if ports & {21}: protocols.add("ftp")
        if ports & {3389}: protocols.add("rdp")
        if any(5900 <= p <= 5909 for p in ports): protocols.add("vnc")
        if ports & {111, 2049}: protocols.add("nfs")
    return protocols


def build_findings(top_hosts: list[Host], nuclei: list[dict[str, Any]], nxc_summary: dict[str, Any]) -> list[dict[str, Any]]:
    findings = []
    for host in top_hosts:
        for svc in sorted(host.services.values(), key=lambda s: s.port):
            if svc.port in HIGH_IMPACT_PORTS:
                severity = "High" if svc.port in {23, 3389, 5985, 5986, 2375, 6379, 9200, 9300} else "Medium"
                findings.append({
                    "status": "inferred",
                    "severity": severity,
                    "host": host.ip,
                    "hostname": host.hostname,
                    "port": svc.port,
                    "service": service_display(svc),
                    "service_name": port_label(svc.port, svc.name),
                    "service_tooltip": service_tooltip(svc.port),
                    "tooltip": service_tooltip(svc.port),
                    "title": f"Internal exposure on {service_display(svc)}",
                    "evidence": f"{svc.protocol}/{svc.port} {svc.name} {svc.product} {svc.version}".strip(),
                    "confidence": "medium",
                    "cves": [],
                    "recommendation": service_recommendation(svc.port),
                })
    for item in nuclei:
        info_block = item.get("info", {})
        classification = info_block.get("classification", {}) if isinstance(info_block.get("classification"), dict) else {}
        cves = []
        for key in ["cve-id", "cve", "cve_ids"]:
            value = classification.get(key) or info_block.get(key)
            if isinstance(value, list):
                cves.extend([str(item).upper() for item in value if str(item).upper().startswith("CVE-")])
            elif isinstance(value, str) and value.upper().startswith("CVE-"):
                cves.append(value.upper())
        cves.extend(extract_cves_from_text(json.dumps(item)))
        cves = sorted(set(cves))
        matched_host = normalized_findings_host(item.get("host") or item.get("matched-at") or "")
        findings.append({
            "status": "confirmed",
            "severity": str(info_block.get("severity", "info")).title(),
            "host": matched_host or str(item.get("host") or item.get("matched-at") or ""),
            "hostname": matched_host,
            "port": None,
            "service": str(info_block.get("reference", item.get("template-id", "")) or "Web"),
            "service_name": "",
            "service_tooltip": "Validate the affected web interface, patching status, and authentication controls.",
            "tooltip": "Validate the affected web interface, patching status, and authentication controls.",
            "title": str(info_block.get("name", item.get("template-id", "Nuclei finding"))),
            "evidence": str(item.get("template-id", "")),
            "confidence": "medium",
            "cves": cves,
            "recommendation": "Review the raw Nuclei JSONL artifact, confirm ownership, and validate configuration impact on the affected web interface.",
        })
    return findings


def host_to_dict(host: Host) -> dict[str, Any]:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
        "netbios_name": host.netbios_name,
        "smb_name": host.smb_name,
        "domain_or_workgroup": host.domain_or_workgroup,
        "mdns_name": host.mdns_name,
        "mac": host.mac,
        "vendor": host.vendor,
        "sources": sorted(host.sources),
        "services": [vars(s) for s in sorted(host.services.values(), key=lambda x: x.port)],
        "score": host.score,
        "ranking_reasons": host.ranking_reasons,
        "role_guess": host.role_guess,
        "role_confidence": host.role_confidence,
        "deep_scanned": host.deep_scanned,
        "dc_candidate": host.dc_candidate,
        "dc_status": host.dc_status,
        "dc_confidence": host.dc_confidence,
        "dc_evidence": host.dc_evidence,
        "screenshot_path": host.screenshot_path,
        "screenshot_embedded": host.screenshot_embedded,
        "screenshot_data_uri": host.screenshot_data_uri,
        "screenshot_mime": host.screenshot_mime,
    }


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


SEVERITY_ORDER = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1, "Informational": 1}


def severity_rank(value: str) -> int:
    return SEVERITY_ORDER.get(str(value).title(), 0)


def severity_class(value: Any) -> str:
    label = str(value or "Info").strip().lower()
    return "info" if label in {"informational", "info"} else re.sub(r"[^a-z0-9_-]+", "-", label)


def finding_matches_host(finding: dict[str, Any], host: Host) -> bool:
    host_names = [normalize_identity_value(item).lower() for item in [host.ip, host.hostname, host.netbios_name, host.smb_name, host.mdns_name, host.domain_or_workgroup] if normalize_identity_value(item)]
    text = " ".join(str(finding.get(key, "")) for key in ["host", "hostname", "service", "title", "evidence", "recommendation", "url", "matched-at"]).lower()
    if any(name and name in text for name in host_names):
        return True
    for key in ["host", "hostname", "matched-at", "url"]:
        value = normalized_findings_host(finding.get(key, "")).lower()
        if value and value in host_names:
            return True
    return False


def host_findings(findings: list[dict[str, Any]], host: Host) -> list[dict[str, Any]]:
    return [finding for finding in findings if finding_matches_host(finding, host)]


def host_highest_severity(findings: list[dict[str, Any]], host: Host) -> str:
    scores = sorted((severity_rank(item.get("severity", "")) for item in host_findings(findings, host)), reverse=True)
    if not scores:
        return "Informational"
    for label, rank in SEVERITY_ORDER.items():
        if rank == scores[0]:
            return label
    return "Informational"


def host_risk_severity(host: Host, findings: list[dict[str, Any]]) -> str:
    severity = host_highest_severity(findings, host)
    if host.dc_status == "confirmed":
        if severity_rank(severity) < severity_rank("High"):
            severity = "High"
    elif host.dc_status == "candidate" and severity_rank(severity) < severity_rank("Medium"):
        severity = "Medium"
    elif severity_rank(severity) < severity_rank("High") and host.score >= 110:
        severity = "High"
    elif severity_rank(severity) < severity_rank("Medium") and host.score >= 55:
        severity = "Medium"
    elif severity_rank(severity) == 0 and host.score >= 20:
        severity = "Low"
    return severity


def host_relevant_cves(findings: list[dict[str, Any]], host: Host) -> list[str]:
    cves = set()
    for item in host_findings(findings, host):
        for cve in item.get("cves", []) or []:
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                cves.add(cve.upper())
    return sorted(cves)


def finding_service_label(finding: dict[str, Any]) -> str:
    service = normalize_identity_value(finding.get("service", ""))
    if service:
        return service
    port = finding.get("port")
    if port not in {None, ""}:
        service_name = normalize_identity_value(finding.get("service_name", ""))
        return f"{port}/{service_name or 'tcp'}"
    return ""


def finding_service_tooltip(finding: dict[str, Any]) -> str:
    return normalize_identity_value(finding.get("service_tooltip") or finding.get("tooltip") or "Validate the affected service and confirm hardening requirements.")


def finding_search_text(finding: dict[str, Any]) -> str:
    return " ".join(
        normalize_identity_value(finding.get(key, ""))
        for key in ["severity", "status", "host", "hostname", "service", "service_name", "title", "evidence", "recommendation", "port"]
    )


def build_report_metrics(
    hosts: dict[str, Host],
    top_hosts: list[Host],
    findings: list[dict[str, Any]],
    dc_candidates: dict[str, dict[str, Any]],
    screenshot_summary: dict[str, Any],
    performance_summary: dict[str, Any],
    ctx: dict[str, Any],
) -> dict[str, Any]:
    severity_counts = {label: 0 for label in ["Critical", "High", "Medium", "Low", "Info"]}
    for item in findings:
        label = str(item.get("severity", "Info")).title()
        if label not in severity_counts:
            label = "Info"
        severity_counts[label] += 1
    open_port_hosts = sum(1 for host in hosts.values() if host.services)
    management_hosts = sum(1 for host in hosts.values() if any(port in MANAGEMENT_PORTS for port in host.services))
    web_hosts = sum(1 for host in hosts.values() if any(port in WEB_PORTS for port in host.services))
    dc_confirmed = sum(1 for item in dc_candidates.values() if str(item.get("status", "")).lower() == "confirmed" or item.get("confirmed"))
    dc_candidates_count = sum(1 for item in dc_candidates.values() if str(item.get("status", "")).lower() == "candidate" and not item.get("confirmed"))
    partial_results = "yes" if performance_summary.get("timeouts") else "no"
    route_warnings = len(ctx.get("route_overlap_warnings", []))
    screenshot_status = screenshot_summary.get("status", "no")
    screenshot_embedded = screenshot_summary.get("embedded", 0)
    screenshot_attempted = screenshot_summary.get("attempted", 0)
    return {
        "hosts_discovered": len(hosts),
        "hosts_with_open_ports": open_port_hosts,
        "critical_findings": severity_counts["Critical"],
        "high_findings": severity_counts["High"],
        "medium_findings": severity_counts["Medium"],
        "management_hosts": management_hosts,
        "web_hosts": web_hosts,
        "dc_confirmed": dc_confirmed,
        "dc_candidates": dc_candidates_count,
        "route_warnings": route_warnings,
        "partial_results": partial_results,
        "screenshots_status": screenshot_status,
        "screenshots_embedded": screenshot_embedded,
        "screenshots_attempted": screenshot_attempted,
        "severity_counts": severity_counts,
        "top_hosts": top_hosts,
        "findings": findings,
        "dc_candidates_map": dc_candidates,
        "performance_summary": performance_summary,
    }


def render_management_summary_table(metrics: dict[str, Any]) -> str:
    rows = [
        ("Hosts discovered", str(metrics["hosts_discovered"]), "All hosts seen during discovery and enrichment."),
        ("Hosts with open ports", str(metrics["hosts_with_open_ports"]), "Hosts with at least one observed service."),
        ("Critical findings", str(metrics["critical_findings"]), "Only confirmed or inferred critical issues."),
        ("High findings", str(metrics["high_findings"]), "Highest-priority exposures in the finding set."),
        ("Medium findings", str(metrics["medium_findings"]), "Useful follow-up and hardening work."),
        ("Exposed management services", str(metrics["management_hosts"]), "SSH, RDP, WinRM, SMB, LDAP, DNS, and similar surfaces."),
        ("Web interfaces found", str(metrics["web_hosts"]), "Internal HTTP or HTTPS panels and admin UIs."),
        ("Domain controller confirmed", "yes" if metrics["dc_confirmed"] else "no", "Strict host-specific evidence only."),
        ("Domain controller candidates", str(metrics["dc_candidates"]), "Credible but still unconfirmed identity targets."),
        ("Route/scope warnings", str(metrics["route_warnings"]), "Overlapping routes or validation notes."),
        ("Scan completed with partial results", metrics["partial_results"], "Timeouts or degraded phases were preserved."),
        ("Screenshots embedded", metrics["screenshots_status"], f"{metrics['screenshots_embedded']}/{metrics['screenshots_attempted']} host screenshots embedded."),
    ]
    return "".join(
        f"<tr><th>{esc(metric)}</th><td>{esc(result)}</td><td>{esc(comment)}</td></tr>"
        for metric, result, comment in rows
    )


def build_priority_findings(top_hosts: list[Host], findings: list[dict[str, Any]], dc_candidates: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for host in top_hosts:
        candidate = dc_candidates.get(host.ip)
        host_findings_list = host_findings(findings, host)
        if candidate:
            title = "Domain controller" if str(candidate.get("status", "")).lower() == "confirmed" or candidate.get("confirmed") else "DC candidate"
            severity = "High" if title == "Domain controller" else "Medium"
            reason = "; ".join(candidate.get("evidence", [])[:2]) or candidate.get("reason", "") or host_service_summary(host)
            key = (host.ip, title)
            if key not in seen:
                items.append({"severity": severity, "host": host.ip, "title": title, "reason": reason})
                seen.add(key)
            continue
        if host_findings_list:
            top = max(host_findings_list, key=lambda item: severity_rank(item.get("severity", "")))
            same_rank = [item for item in host_findings_list if severity_rank(item.get("severity", "")) == severity_rank(top.get("severity", ""))]
            titles = [str(item.get("title", "")).strip() for item in same_rank if str(item.get("title", "")).strip()]
            title = titles[0] if len(set(titles)) == 1 else f"{len(set(titles))} related findings"
            reason = str(top.get("evidence") or top.get("recommendation") or host_service_summary(host))
            key = (host.ip, title)
            if key not in seen:
                items.append({"severity": str(top.get("severity", "Medium")).title(), "host": host.ip, "title": title, "reason": reason})
                seen.add(key)
            continue
        mgmt_services = [svc for svc in sorted(host.services.values(), key=lambda svc: svc.port) if svc.port in MANAGEMENT_PORTS]
        web_services = [svc for svc in sorted(host.services.values(), key=lambda svc: svc.port) if svc.port in WEB_PORTS]
        if mgmt_services:
            severity = "High" if any(svc.port in {3389, 5985, 5986, 2375, 6379, 9200, 9300, 445, 389, 636} for svc in mgmt_services) else "Medium"
            title = "Remote administration services exposed"
            reason = f"{', '.join(service_display(svc) for svc in mgmt_services[:4])} are reachable from this segment."
            key = (host.ip, title)
            if key not in seen:
                items.append({"severity": severity, "host": host.ip, "title": title, "reason": reason})
                seen.add(key)
            continue
        if len(web_services) >= 2:
            title = "Multiple web interfaces detected"
            reason = f"{', '.join(service_display(svc) for svc in web_services[:4])} should be validated for authentication and patching."
            key = (host.ip, title)
            if key not in seen:
                items.append({"severity": "Medium", "host": host.ip, "title": title, "reason": reason})
                seen.add(key)
    items.sort(key=lambda item: (-severity_rank(item["severity"]), -next((host.score for host in top_hosts if host.ip == item["host"]), 0), item["host"], item["title"]))
    return items[:5]


def build_ceo_summary(metrics: dict[str, Any], priority_items: list[dict[str, str]]) -> str:
    critical = metrics["critical_findings"]
    high = metrics["high_findings"]
    management_hosts = metrics["management_hosts"]
    web_hosts = metrics["web_hosts"]
    dc_confirmed = metrics["dc_confirmed"]
    dc_candidates = metrics["dc_candidates"]
    hosts = metrics["hosts_discovered"]
    partial = metrics["partial_results"]
    sentences = []
    host_word = "host" if hosts == 1 else "hosts"
    surface_word = "surface" if management_hosts == 1 else "surfaces"
    if critical or high:
        sentences.append(f"The scan did not prove active compromise, but it did surface {critical} critical and {high} high-priority findings that deserve follow-up.")
    else:
        sentences.append("The environment looks broadly healthy. The scan mainly found a small number of reachable services that should be validated for business need and hardening.")
    sentences.append(f"The main operational risk is the {management_hosts} internally reachable management or remote-administration {surface_word} across {hosts} discovered {host_word}, because in a mixed-trust home-office or small-office network a single compromised device can become a pivot point.")
    if web_hosts:
        sentences.append(f"{web_hosts} host(s) also expose web interfaces, so ownership, authentication, and update status should be checked before the interfaces are left reachable on this segment.")
    if dc_confirmed or dc_candidates:
        if dc_confirmed:
            if dc_candidates:
                sentences.append(f"Domain-controller detection was deliberately strict: {dc_confirmed} host(s) were confirmed with host-specific evidence, while {dc_candidates} remained only candidates.")
            else:
                sentences.append(f"Domain-controller detection was deliberately strict: {dc_confirmed} host(s) were confirmed with host-specific evidence and no additional candidates remained.")
        else:
            sentences.append(f"Directory-style services were only treated as candidates when multiple host-specific indicators lined up, which reduces the chance of false positives on router or printer-style devices.")
    if partial == "yes":
        sentences.append("A few commands timed out or returned partial output, so the report should be used as a prioritization aid rather than a final inventory.")
    sentences.append("The right next step is to validate which exposed services are actually required, then harden, patch, or isolate the highest-ranked hosts first.")
    if priority_items:
        sentences.append(f"The most urgent follow-up items are centered on {', '.join(item['host'] for item in priority_items[:3])}.")
    return " ".join(sentences)


def render_command_entry(command: dict[str, str]) -> str:
    return f"""
<div class="command-entry">
  <div class="command-entry-head">
    <div>
      <div class="command-label">{esc(command['label'])}</div>
      <div class="muted">Timeout: {esc(command['timeout'])}</div>
    </div>
    <button class="copy-command" type="button" data-command="{esc(command['command'])}">Copy</button>
  </div>
  <code class="command-code">{esc(command['command'])}</code>
</div>
"""


def render_host_card(host: Host, findings: list[dict[str, Any]], dc_candidates: dict[str, dict[str, Any]]) -> str:
    severity = host_risk_severity(host, findings)
    open_ports = len(host.services)
    dc_badge = host_dc_badge_text(host, dc_candidates)
    badge_html = "".join(
        [
            f"<span class='badge severity-{severity_class(severity)}'>{esc(severity)}</span>",
            f"<span class='badge'>Score {esc(host.score)}</span>",
            f"<span class='badge'>{esc(open_ports)} open ports</span>",
            f"<span class='badge'>{esc(len(host.services))} services</span>",
            f"<span class='badge dc'>{esc(dc_badge)}</span>" if dc_badge else "",
        ]
    )
    evidence_items = host.ranking_reasons[:4] or ["Live host discovered with no high-impact service evidence."]
    evidence_html = "".join(f"<li>{esc(item)}</li>" for item in evidence_items)
    findings_list = top_host_findings(findings, host)
    findings_html = "".join(
        f"<li><span class='badge severity-{severity_class(item.get('severity', 'Info'))}'>{esc(item.get('severity', 'Info'))}</span> {esc(item.get('title', 'Finding'))} <span class='muted'>({esc(item.get('status', 'unknown'))})</span></li>"
        for item in findings_list
    ) or "<li class='muted'>No host-specific findings recorded.</li>"
    commands = host_verification_commands(host, dc_candidates)
    command_entries = "".join(render_command_entry(cmd) for cmd in commands)
    screenshot_html = ""
    if host.screenshot_data_uri:
        screenshot_html = f"<figure class='host-shot'><img src='{esc(host.screenshot_data_uri)}' alt='Screenshot for {esc(host.ip)}'></figure>"
    layout_class = "with-shot" if host.screenshot_data_uri else "no-shot"
    dc_evidence = ""
    if dc_badge:
        dc_evidence = f"<div class='host-subline'><strong>DC evidence:</strong> {esc('; '.join(host.dc_evidence[:4]) or 'none')}</div>"
    return f"""
<article class="host-card">
  <div class="host-head">
    <div class="host-head-main">
      <div class="host-title">{esc(host.ip)}</div>
      <div class="host-subline">{esc(host_identity_summary(host))}</div>
      <div class="host-subline"><strong>Role:</strong> {esc(host.role_guess or 'unknown')}</div>
      <div class="host-subline"><strong>Key services:</strong> {esc(host_service_summary(host))}</div>
    </div>
    <div class="host-badges">{badge_html}</div>
  </div>
  <div class="svc-row">{host_service_chips(host)}</div>
  <div class="host-layout {layout_class}">
    <div class="host-left">
      <div class="host-summary-line"><strong>Open ports:</strong> {esc(open_ports)} | <strong>Service count:</strong> {esc(len(host.services))}</div>
      {dc_evidence}
      <div class="host-section">
        <div class="host-section-title">Key evidence</div>
        <ul class="host-list">{evidence_html}</ul>
      </div>
      <div class="host-section">
        <div class="host-section-title">Top host-specific findings</div>
        <ul class="host-list">{findings_html}</ul>
      </div>
      <details class="command-details">
        <summary>Verification commands ({len(commands)})</summary>
        <div class="command-list">{command_entries or "<div class='muted'>No host-specific validation command generated.</div>"}</div>
      </details>
    </div>
    {screenshot_html}
  </div>
</article>
"""


def render_findings_tab(findings: list[dict[str, Any]]) -> str:
    chips = ["all", "critical", "high", "medium", "low", "info"]
    chip_html = "".join(
        f"<button class='filter-chip{' active' if chip == 'all' else ''}' type='button' data-finding-filter='{chip}'>{chip.title()}</button>"
        for chip in chips
    )
    rows = []
    for item in findings:
        service = finding_service_label(item)
        service_title = finding_service_tooltip(item)
        search = finding_search_text(item)
        rows.append(
            f"<tr class='finding-row' data-finding-severity='{severity_class(item.get('severity'))}' data-search='{esc(search)}'>"
            f"<td><span class='badge severity-{severity_class(item.get('severity'))}'>{esc(item.get('severity', 'Info'))}</span></td>"
            f"<td>{esc(item.get('status', ''))}</td>"
            f"<td class='mono'>{esc(item.get('host', ''))}</td>"
            f"<td><span class='svc-chip' title='{esc(service_title)}'>{esc(service or '—')}</span></td>"
            f"<td>{esc(item.get('title', ''))}</td>"
            f"<td><details><summary>Evidence</summary><pre>{esc(item.get('evidence', ''))}</pre></details></td>"
            f"<td>{esc(item.get('recommendation', ''))}</td>"
            f"</tr>"
        )
    body = "".join(rows) or "<tr><td colspan='7' class='muted'>No findings generated.</td></tr>"
    return f"""
<section class="tab-panel" id="tab-findings" role="tabpanel" aria-labelledby="tab-findings-btn">
  <div class="tab-panel-head">
    <h2>Findings</h2>
    <div class="muted">Search by host, service, evidence, or recommendation. Evidence stays collapsed by default.</div>
  </div>
  <div class="findings-toolbar">
    <form class="search-box" id="findingSearch">
      <input id="findingQuery" type="search" placeholder="Search findings by host, service, evidence, or recommendation" autocomplete="off">
      <button type="submit">Search</button>
    </form>
    <div class="filter-chip-row">{chip_html}</div>
  </div>
  <div class="table-wrap">
    <table class="finding-table">
      <thead>
        <tr><th>Severity</th><th>Status</th><th>Host</th><th>Service</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr>
      </thead>
      <tbody id="findingsBody">{body}</tbody>
    </table>
  </div>
</section>
"""


def render_verification_tab(top_hosts: list[Host], dc_candidates: dict[str, dict[str, Any]], performance_summary: dict[str, Any]) -> str:
    command_rows = []
    for host in top_hosts:
        for cmd in host_verification_commands(host, dc_candidates):
            command_rows.append(
                f"<tr><td class='mono'>{esc(host.ip)}</td><td>{esc(host.hostname or host.netbios_name or 'unknown')}</td><td>{esc(cmd['label'])}</td><td>{esc(cmd['timeout'])}</td><td>{esc('suggested')}</td><td><code class='command-inline'>{esc(cmd['command'])}</code></td><td><button class='copy-command' type='button' data-command='{esc(cmd['command'])}'>Copy</button></td></tr>"
            )
    command_body = "".join(command_rows) or "<tr><td colspan='7' class='muted'>No verification commands generated.</td></tr>"
    timeout_rows = []
    for item in performance_summary.get("timeouts", []):
        timeout_rows.append(
            f"<tr><td>{esc(item.get('name'))}</td><td>{esc(item.get('exit_code'))}</td><td>{esc(item.get('timeout_seconds'))}</td><td>{esc(item.get('duration_seconds'))}</td><td>{esc(command_record_status(item))}</td></tr>"
        )
    timeout_body = "".join(timeout_rows) or "<tr><td colspan='5' class='muted'>No timeouts or partial results recorded.</td></tr>"
    return f"""
<section class="tab-panel" id="tab-verification" role="tabpanel" aria-labelledby="tab-verification-btn">
  <div class="tab-panel-head">
    <h2>Verification Commands</h2>
    <div class="muted">These are safe follow-up checks for the top hosts. Copy a command to clipboard, then run it manually if needed.</div>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Hostname</th><th>Purpose</th><th>Timeout</th><th>Status</th><th>Command</th><th>Copy</th></tr></thead>
      <tbody>{command_body}</tbody>
    </table>
  </div>
  <h3>Timeouts and partial results</h3>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Command</th><th>Exit</th><th>Timeout</th><th>Duration</th><th>Status</th></tr></thead>
      <tbody>{timeout_body}</tbody>
    </table>
  </div>
</section>
"""


def render_scan_details_tab(
    ctx: dict[str, Any],
    profile: dict[str, str],
    deps: dict[str, Any],
    dc_candidates: dict[str, dict[str, Any]],
    performance_summary: dict[str, Any],
    screenshot_summary: dict[str, Any],
    scan_meta: dict[str, Any],
) -> str:
    validated_networks = ctx.get("validated_networks", ctx.get("networks", []))
    route_samples = ctx.get("route_get_samples", [])
    overlap_warnings = ctx.get("route_overlap_warnings", [])
    dc_rows = "".join(
        f"<tr><td class='mono'>{esc(item.get('ip'))}</td><td>{esc(item.get('hostname') or item.get('netbios_name') or '')}</td><td>{esc(item.get('status') or ('confirmed' if item.get('confirmed') else 'candidate'))}</td><td>{esc(item.get('confidence'))}</td><td>{esc(item.get('reason'))}</td><td>{esc(', '.join(map(str, item.get('open_ports', []))) or 'none')}</td><td>{esc('; '.join(item.get('evidence', [])) or 'none')}</td><td>{esc('; '.join(item.get('source_artifacts', [])) or 'none')}</td></tr>"
        for item in dc_candidates.values()
    ) or "<tr><td colspan='8' class='muted'>No domain-controller candidates discovered.</td></tr>"
    route_sample_rows = "".join(
        f"<tr><td>{esc(item.get('network'))}</td><td>{esc(item.get('representative_ip'))}</td><td>{esc(item.get('effective_dev') or 'unknown')}</td><td><pre>{esc(item.get('stdout') or item.get('stderr'))}</pre></td></tr>"
        for item in route_samples
    ) or "<tr><td colspan='4' class='muted'>No route lookup samples recorded.</td></tr>"
    overlap_rows = "".join(
        f"<tr><td>{esc(item.get('network'))}</td><td>{esc(item.get('effective_dev'))}</td><td>{esc(item.get('effective_via') or 'n/a')}</td><td>{esc('; '.join(r.get('dev', '') for r in item.get('competing_routes', [])) or 'none')}</td></tr>"
        for item in overlap_warnings
    ) or "<tr><td colspan='4' class='muted'>No overlapping routes were detected.</td></tr>"
    tools_rows = []
    for name, data in sorted(deps.items()):
        tools_rows.append(
            f"<tr><td>{esc(name)}</td><td>{esc('yes' if data.get('installed') else 'no')}</td><td>{esc(data.get('path') or data.get('stdout') or '')}</td><td>{esc(data.get('exit_code') if data.get('installed') else '')}</td></tr>"
        )
    tools_body = "".join(tools_rows) or "<tr><td colspan='4' class='muted'>No tool version data recorded.</td></tr>"
    raw_meta = {
        "run_id": scan_meta.get("run_id"),
        "hosts_discovered": len(scan_meta.get("hosts", [])),
        "top_hosts": [item.get("ip") for item in scan_meta.get("top_hosts", [])],
        "findings": len(scan_meta.get("findings", [])),
        "nxc_protocols": scan_meta.get("nxc", {}).get("selected_protocols", []),
        "screenshot_status": screenshot_summary.get("status", "no"),
        "partial_results": scan_meta.get("performance", {}).get("timeouts", []) != [],
    }
    return f"""
<section class="tab-panel" id="tab-scan-details" role="tabpanel" aria-labelledby="tab-scan-details-btn">
  <div class="tab-panel-head">
    <h2>Scan Details / Misc</h2>
    <div class="muted">Routing, tool versions, Codex settings, DC evidence, and other technical context live here.</div>
  </div>
  <div class="section-grid">
    <div class="panel"><strong>Selected interface</strong><div>{esc(ctx['interface'])}</div><div class="muted">Codex profile: {esc(profile.get('reasoning_profile', ''))} | model: {esc(profile.get('model', ''))}</div></div>
    <div class="panel"><strong>Validated networks</strong><div>{''.join(f"<span class='pill'>{esc(net)}</span>" for net in validated_networks) or '<span class=\"muted\">none</span>'}</div></div>
    <div class="panel"><strong>Excluded routes</strong><div class="muted">{esc('; '.join(ctx.get('route_excluded_networks', [])) or 'none')}</div></div>
    <div class="panel"><strong>Route warnings</strong><div>{esc(len(overlap_warnings))}</div><div class="muted">{esc('; '.join(item.get('network', '') + ' -> ' + (item.get('effective_dev') or 'unknown') for item in overlap_warnings) or 'none')}</div></div>
    <div class="panel"><strong>Screenshots embedded</strong><div>{esc(screenshot_summary.get('status', 'no'))}</div><div class="muted">{esc(f"{screenshot_summary.get('embedded', 0)}/{screenshot_summary.get('attempted', 0)} embedded")}</div></div>
  </div>
  <h3>Route validation evidence</h3>
  <div class="table-wrap"><table><thead><tr><th>Network</th><th>Representative IP</th><th>Effective dev</th><th>Route output</th></tr></thead><tbody>{route_sample_rows}</tbody></table></div>
  <h3>Overlap details</h3>
  <div class="table-wrap"><table><thead><tr><th>Network</th><th>Effective dev</th><th>Via</th><th>Competing devs</th></tr></thead><tbody>{overlap_rows}</tbody></table></div>
  <h3>Domain controller evidence</h3>
  <div class="table-wrap"><table><thead><tr><th>IP</th><th>Hostname</th><th>Status</th><th>Confidence</th><th>Reason</th><th>Ports</th><th>Evidence</th><th>Artifacts</th></tr></thead><tbody>{dc_rows}</tbody></table></div>
  <h3>Tool versions</h3>
  <div class="table-wrap"><table><thead><tr><th>Tool</th><th>Installed</th><th>Path / artifact</th><th>Exit</th></tr></thead><tbody>{tools_body}</tbody></table></div>
  <h3>Assumptions and limitations</h3>
  <p>The scanner only performs safe, bounded, internal discovery and enumeration. It does not run brute force, password spraying, credential dumping, exploit modules, coercion, password changes, or state-changing tests. Results depend on host firewalls, Wi-Fi isolation, timing, privileges, and optional tool availability.</p>
  <details class="command-details">
    <summary>Raw scan metadata</summary>
    <pre>{esc(json.dumps(raw_meta, indent=2, sort_keys=True))}</pre>
  </details>
</section>
"""


def report_css() -> str:
    return """
:root {
  color-scheme: light;
  --font-sans: "IBM Plex Sans", "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  --font-header: "Space Grotesk", "Segoe UI Semibold", "Helvetica Neue", Arial, sans-serif;
  --font-mono: "JetBrains Mono", "SFMono-Regular", "Consolas", "Liberation Mono", monospace;
  --bg: #fafafa;
  --bg-subtle: #f4f4f4;
  --ui: #efefef;
  --line: #e7e7e7;
  --border: #dddddd;
  --border-hover: #cfcfcf;
  --ink: #000000;
  --text: #171717;
  --surface: #ffffff;
  --muted: #666666;
  --accent: #000000;
  --on-accent: #ffffff;
  --header-bg: rgba(255,255,255,.86);
  --glass-bg: rgba(255,255,255,.58);
  --glass-border: rgba(0,0,0,.08);
  --row-hover: #fafafa;
  --sev-crit-bg: #fce4e4;
  --sev-crit-bd: #f5c6c7;
  --sev-crit-fg: #b91212;
  --sev-high-bg: #fceee3;
  --sev-high-bd: #f6dec8;
  --sev-high-fg: #c2410c;
  --sev-med-bg: #fbf3dd;
  --sev-med-bd: #f0e4be;
  --sev-med-fg: #b07a06;
  --sev-low-bg: #e6f6ee;
  --sev-low-bd: #cdebd8;
  --sev-low-fg: #0e9e57;
}
html[data-theme="dark"] {
  color-scheme: dark;
  --bg: #0a0a0a;
  --bg-subtle: #111111;
  --ui: #1a1a1a;
  --line: rgba(255,255,255,.10);
  --border: rgba(255,255,255,.14);
  --border-hover: rgba(255,255,255,.22);
  --ink: #ededed;
  --text: #ededed;
  --surface: #161616;
  --muted: #a1a1a1;
  --accent: #ededed;
  --on-accent: #0a0a0a;
  --header-bg: rgba(10,10,10,.86);
  --glass-bg: rgba(255,255,255,.05);
  --glass-border: rgba(255,255,255,.12);
  --row-hover: rgba(255,255,255,.035);
  --sev-crit-bg: rgba(229,72,77,.15);
  --sev-crit-bd: rgba(229,72,77,.25);
  --sev-crit-fg: #ff6369;
  --sev-high-bg: rgba(255,128,31,.12);
  --sev-high-bd: rgba(255,128,31,.22);
  --sev-high-fg: #ff8b3e;
  --sev-med-bg: rgba(255,178,36,.12);
  --sev-med-bd: rgba(255,178,36,.22);
  --sev-med-fg: #ffb224;
  --sev-low-bg: rgba(70,167,88,.12);
  --sev-low-bd: rgba(70,167,88,.22);
  --sev-low-fg: #46a758;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: radial-gradient(circle at 20% -10%, var(--ui), transparent 34rem), linear-gradient(180deg, var(--bg), var(--bg-subtle));
  color: var(--text);
  font: 14px/1.6 var(--font-sans);
}
.site-header {
  position: sticky;
  top: 0;
  z-index: 20;
  background: var(--header-bg);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--line);
}
.header-inner, main { max-width: 1240px; margin: 0 auto; padding: 1.5rem; }
.header-inner { display: flex; align-items: center; justify-content: space-between; gap: 1rem; }
h1, h2, h3, .host-title, .button, .tab-button, .theme-toggle, .summary-table th, .summary-table td strong { font-family: var(--font-header); }
h1 { margin: 0; font-size: clamp(1.6rem, 4vw, 2.7rem); letter-spacing: -.04em; color: var(--ink); }
h2 { margin: 0; font-size: 1.3rem; letter-spacing: -.03em; }
h3 { margin: 1.25rem 0 .65rem; font-size: 1rem; letter-spacing: -.02em; }
p { margin: .4rem 0 0; }
main { display: grid; gap: 1rem; }
section, .host-card, .panel, .note, .command-entry, .summary-table, .tab-button, .filter-chip { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; }
section { padding: 1.25rem; box-shadow: 0 18px 50px rgba(0,0,0,.04); }
.muted { color: var(--muted); }
.mono, code, pre { font-family: var(--font-mono); }
.button, .theme-toggle, .search-box button, .copy-command, .tab-button, .filter-chip {
  background: var(--accent);
  color: var(--on-accent);
  border: none;
  border-radius: 8px;
  padding: .55rem .95rem;
  font: inherit;
  font-weight: 600;
  cursor: pointer;
  transition: opacity .2s, border-color .2s, background .2s;
}
.button:hover, .theme-toggle:hover, .search-box button:hover, .copy-command:hover, .tab-button:hover, .filter-chip:hover { opacity: .82; }
.summary-table { width: 100%; border-collapse: collapse; overflow: hidden; }
.summary-table th, .summary-table td { border-bottom: 1px solid var(--line); padding: .9rem .8rem; text-align: left; vertical-align: top; }
.summary-table th { width: 18rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; font-size: .78rem; }
.summary-table td { width: auto; }
.summary-table tr:last-child th, .summary-table tr:last-child td { border-bottom: none; }
.summary-table tr:hover { background: var(--row-hover); }
.summary-table .summary-result { white-space: nowrap; font-weight: 700; }
.summary-table .summary-result.yes { color: var(--sev-low-fg); }
.summary-table .summary-result.no { color: var(--muted); }
.summary-table .summary-result.partial { color: var(--sev-med-fg); }
.summary-table .summary-result.high { color: var(--sev-high-fg); }
.summary-table .summary-result.critical { color: var(--sev-crit-fg); }
.priority-list { display: grid; gap: .75rem; margin: .25rem 0 0; padding: 0; list-style: none; }
.priority-list li { padding: .85rem .9rem; border: 1px solid var(--line); border-radius: 10px; background: var(--glass-bg); }
.priority-line { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
.tabs { display: flex; flex-wrap: wrap; gap: .5rem; padding: 0 1.5rem; max-width: 1240px; margin: 0 auto; }
.tab-button { color: var(--text); background: var(--surface); }
.tab-button.active { border-color: var(--border-hover); box-shadow: inset 0 0 0 1px var(--border-hover); }
.tab-panel { display: none; }
.tab-panel.active { display: block; }
.tab-panel-head { display: flex; flex-wrap: wrap; justify-content: space-between; gap: .75rem; align-items: baseline; margin-bottom: 1rem; }
.tab-panel-head .muted { max-width: 58rem; }
.section-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; }
.panel { padding: 1rem; background: var(--glass-bg); border-color: var(--glass-border); }
.note { background: var(--glass-bg); border-color: var(--glass-border); padding: 1rem; }
.stack { display: grid; gap: 1rem; }
.host-card { padding: 1.2rem; }
.host-card:hover { border-color: var(--border-hover); }
.host-head { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start; }
.host-head-main { min-width: 0; }
.host-title { font-size: 1.3rem; font-weight: 800; letter-spacing: -.03em; margin-bottom: .15rem; }
.host-subline { color: var(--muted); margin-top: .1rem; }
.host-badges { display: flex; gap: .5rem; flex-wrap: wrap; justify-content: flex-end; align-items: flex-start; }
.badge { display: inline-flex; align-items: center; justify-content: center; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; text-transform: uppercase; background: var(--ui); border: 1px solid var(--border); color: var(--text); }
.severity-critical { background: var(--sev-crit-bg); border-color: var(--sev-crit-bd); color: var(--sev-crit-fg); }
.severity-high { background: var(--sev-high-bg); border-color: var(--sev-high-bd); color: var(--sev-high-fg); }
.severity-medium { background: var(--sev-med-bg); border-color: var(--sev-med-bd); color: var(--sev-med-fg); }
.severity-low { background: var(--sev-low-bg); border-color: var(--sev-low-bd); color: var(--sev-low-fg); }
.severity-info { background: var(--ui); border-color: var(--border); color: var(--muted); }
.dc { background: var(--glass-bg); border-color: var(--glass-border); }
.pill, .svc-chip { display: inline-flex; align-items: center; gap: .25rem; padding: .28rem .5rem; border-radius: 999px; background: var(--ui); border: 1px solid var(--border); margin: 0 .4rem .4rem 0; font-size: 12px; }
.svc-chip-muted { color: var(--muted); }
.svc-row { margin: .75rem 0 0; }
.host-layout { display: grid; gap: 1rem; margin-top: .95rem; }
.host-layout.with-shot { grid-template-columns: minmax(0, 1.2fr) minmax(320px, .8fr); align-items: start; }
.host-left { min-width: 0; }
.host-summary-line { margin-bottom: .5rem; }
.host-section { margin-top: .9rem; padding: .85rem .9rem; border: 1px solid var(--line); border-radius: 10px; background: var(--glass-bg); }
.host-section-title { font-family: var(--font-header); font-weight: 700; margin-bottom: .5rem; }
.host-list { margin: 0; padding-left: 1.1rem; }
.host-list li { margin-bottom: .4rem; }
.host-shot img { width: 100%; aspect-ratio: 16 / 10; object-fit: cover; border-radius: 12px; border: 1px solid var(--border); background: var(--bg-subtle); }
.command-details { margin-top: .9rem; }
.command-details summary { cursor: pointer; font-family: var(--font-header); font-weight: 700; color: var(--ink); }
.command-list { display: grid; gap: .75rem; margin-top: .75rem; }
.command-entry { padding: .85rem; background: var(--glass-bg); border-color: var(--glass-border); }
.command-entry-head { display: flex; justify-content: space-between; gap: .8rem; align-items: flex-start; margin-bottom: .45rem; }
.command-label { font-family: var(--font-header); font-weight: 700; }
.command-code, code.command-inline { display: block; white-space: pre-wrap; background: var(--bg-subtle); border: 1px solid var(--line); border-radius: 8px; padding: .7rem; overflow-x: auto; color: var(--text); font-size: 13px; }
.command-inline { display: inline-block; }
.copy-command { padding: .4rem .75rem; font-size: 12px; }
.findings-toolbar { display: flex; flex-wrap: wrap; gap: .75rem; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
.search-box { display: flex; align-items: center; gap: .5rem; border: 1px solid var(--border); border-radius: 10px; background: var(--surface); padding: .25rem .25rem .25rem .95rem; min-width: min(100%, 34rem); flex: 1 1 34rem; }
.search-box input { border: none; outline: none; background: transparent; color: var(--text); font-family: var(--font-sans); width: 100%; min-width: 0; }
.filter-chip-row { display: flex; flex-wrap: wrap; gap: .5rem; }
.filter-chip { color: var(--text); background: var(--surface); }
.filter-chip.active { border-color: var(--border-hover); box-shadow: inset 0 0 0 1px var(--border-hover); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { border-bottom: 1px solid var(--line); padding: .95rem .75rem; text-align: left; vertical-align: top; }
th { font-family: var(--font-header); font-weight: 700; color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }
tr:hover { background: var(--row-hover); }
pre { margin: 0; white-space: pre-wrap; background: var(--bg-subtle); border: 1px solid var(--line); border-radius: 8px; padding: .9rem; overflow-x: auto; color: var(--text); font-size: 13px; }
details summary { cursor: pointer; font-family: var(--font-header); font-weight: 700; }
.finding-table td:nth-child(1), .finding-table td:nth-child(2), .finding-table td:nth-child(3), .finding-table td:nth-child(4) { white-space: nowrap; }
@media (max-width: 900px) {
  .header-inner { flex-direction: column; align-items: flex-start; }
  .host-head { flex-direction: column; }
  .host-badges { justify-content: flex-start; }
  .host-layout.with-shot { grid-template-columns: 1fr; }
  .search-box { min-width: 0; }
}
"""


def report_js() -> str:
    return """
(function () {
  var meta = document.querySelector('meta[name="theme-color"]');
  var themeToggle = document.getElementById('themeToggle');
  var tabs = Array.prototype.slice.call(document.querySelectorAll('.tab-button'));
  var panels = Array.prototype.slice.call(document.querySelectorAll('.tab-panel'));
  var storedTab = localStorage.getItem('c3po-report-tab') || 'top-hosts';
  var storedTheme = localStorage.getItem('c3po-theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  var rows = Array.prototype.slice.call(document.querySelectorAll('.finding-row'));
  var queryInput = document.getElementById('findingQuery');
  var queryForm = document.getElementById('findingSearch');
  var severityFilter = 'all';
  var tabIds = tabs.map(function (tab) { return tab.dataset.tabTarget; });
  if (tabIds.indexOf(storedTab) === -1) storedTab = 'top-hosts';
  if (storedTheme !== 'dark' && storedTheme !== 'light') storedTheme = 'light';

  function applyTheme(theme) {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    localStorage.setItem('c3po-theme', theme);
    if (meta) meta.setAttribute('content', theme === 'dark' ? '#0A0A0A' : '#FAFAFA');
  }

  function activateTab(target) {
    var tabId = target || 'top-hosts';
    tabs.forEach(function (tab) {
      var active = tab.dataset.tabTarget === tabId;
      tab.classList.toggle('active', active);
      tab.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    panels.forEach(function (panel) {
      panel.classList.toggle('active', panel.id === 'tab-' + tabId);
    });
    localStorage.setItem('c3po-report-tab', tabId);
  }

  function applyFindingFilters() {
    var query = (queryInput && queryInput.value ? queryInput.value : '').trim().toLowerCase();
    rows.forEach(function (row) {
      var matchesText = !query || (row.dataset.search || row.textContent).toLowerCase().indexOf(query) !== -1;
      var matchesSeverity = severityFilter === 'all' || row.dataset.findingSeverity === severityFilter;
      row.style.display = matchesText && matchesSeverity ? '' : 'none';
    });
  }

  function copyCommand(button) {
    var command = button.getAttribute('data-command') || '';
    if (!command) return;
    var revert = function (text) {
      button.textContent = text;
      window.setTimeout(function () { button.textContent = 'Copy'; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(command).then(function () { revert('Copied'); }, function () { revert('Copy failed'); });
      return;
    }
    var temp = document.createElement('textarea');
    temp.value = command;
    temp.setAttribute('readonly', 'readonly');
    temp.style.position = 'absolute';
    temp.style.left = '-9999px';
    document.body.appendChild(temp);
    temp.select();
    try {
      document.execCommand('copy');
      revert('Copied');
    } catch (err) {
      revert('Copy failed');
    }
    document.body.removeChild(temp);
  }

  applyTheme(storedTheme);
  activateTab(storedTab);

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      var nextTheme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      applyTheme(nextTheme);
    });
  }

  tabs.forEach(function (tab) {
    tab.addEventListener('click', function () {
      activateTab(tab.dataset.tabTarget);
    });
  });

  document.querySelectorAll('[data-finding-filter]').forEach(function (chip) {
    chip.addEventListener('click', function () {
      severityFilter = chip.dataset.findingFilter || 'all';
      document.querySelectorAll('[data-finding-filter]').forEach(function (item) {
        item.classList.toggle('active', item === chip);
      });
      applyFindingFilters();
    });
  });

  if (queryInput) queryInput.addEventListener('keyup', applyFindingFilters);
  if (queryForm) queryForm.addEventListener('submit', function (event) { event.preventDefault(); applyFindingFilters(); });

  document.addEventListener('click', function (event) {
    var button = event.target.closest('.copy-command');
    if (button) copyCommand(button);
  });
})();
"""


def render_report(
    outdir: Path,
    ctx: dict[str, Any],
    hosts: dict[str, Host],
    top_hosts: list[Host],
    findings: list[dict[str, Any]],
    deps: dict[str, Any],
    profile: dict[str, str],
    nxc_summary: dict[str, Any],
    dc_candidates: dict[str, dict[str, Any]],
    performance_summary: dict[str, Any],
    screenshot_summary: dict[str, Any] | None = None,
) -> Path:
    report = outdir / "report.html"
    if screenshot_summary is None:
        screenshot_summary = embed_screenshots(top_hosts, outdir)
    metrics = build_report_metrics(hosts, top_hosts, findings, dc_candidates, screenshot_summary, performance_summary, ctx)
    priority_items = build_priority_findings(top_hosts, findings, dc_candidates)
    ceo_summary = build_ceo_summary(metrics, priority_items)
    management_rows = render_management_summary_table(metrics)
    priority_html = "".join(
        f"<li><div class='priority-line'><span class='badge severity-{severity_class(item['severity'])}'>{esc(item['severity'])}</span><strong>{esc(item['host'])}</strong><span>{esc(item['title'])}</span></div><div class='muted'>{esc(item['reason'])}</div></li>"
        for item in priority_items
    ) or "<li class='muted'>No high-priority items were produced.</li>"
    top_hosts_html = "".join(render_host_card(host, findings, dc_candidates) for host in top_hosts) or "<div class='muted'>No top hosts available.</div>"
    findings_tab = render_findings_tab(findings)
    verification_tab = render_verification_tab(top_hosts, dc_candidates, performance_summary)
    scan_meta = {
        "run_id": outdir.name,
        "hosts": [host_to_dict(h) for h in hosts.values()],
        "top_hosts": [host_to_dict(h) for h in top_hosts],
        "findings": findings,
        "nxc": nxc_summary,
        "performance": performance_summary,
    }
    scan_details_tab = render_scan_details_tab(ctx, profile, deps, dc_candidates, performance_summary, screenshot_summary, scan_meta)
    try:
        run_stamp = datetime.strptime(outdir.name, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
        run_stamp_suffix = " local"
    except ValueError:
        run_stamp = outdir.name
        run_stamp_suffix = ""
    subtitle = f"Interface: {ctx['interface']} | Scope: {', '.join(map(str, ctx.get('validated_networks', ctx.get('networks', [])))) or 'none'} | Run: {run_stamp}{run_stamp_suffix}"
    report.write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#FAFAFA">
<title>C3PO Local Scanner Report</title>
<script>{report_js()}</script>
<style>{report_css()}</style></head><body>
<header class="site-header"><div class="header-inner"><div><h1>C3PO Local Scanner Report</h1><p class="muted">{esc(subtitle)}</p></div><button class="theme-toggle" id="themeToggle" type="button">Toggle theme</button></div></header>
<main>
<section id="executive-summary">
  <h2>Management Summary</h2>
  <div class="table-wrap"><table class="summary-table"><tbody>{management_rows}</tbody></table></div>
  <div class="note" style="margin-top:1rem"><strong>CEO Summary</strong><p>{esc(ceo_summary)}</p></div>
  <div class="note" style="margin-top:1rem"><strong>Priority Findings</strong><ul class="priority-list">{priority_html}</ul></div>
</section>
<nav class="tabs" role="tablist" aria-label="Report sections">
  <button class="tab-button active" id="tab-top-hosts-btn" role="tab" aria-selected="true" aria-controls="tab-top-hosts" data-tab-target="top-hosts" type="button">Top Host Cards</button>
  <button class="tab-button" id="tab-findings-btn" role="tab" aria-selected="false" aria-controls="tab-findings" data-tab-target="findings" type="button">Findings</button>
  <button class="tab-button" id="tab-verification-btn" role="tab" aria-selected="false" aria-controls="tab-verification" data-tab-target="verification" type="button">Verification Commands</button>
  <button class="tab-button" id="tab-scan-details-btn" role="tab" aria-selected="false" aria-controls="tab-scan-details" data-tab-target="scan-details" type="button">Scan Details / Misc</button>
</nav>
<section class="tab-panel active" id="tab-top-hosts" role="tabpanel" aria-labelledby="tab-top-hosts-btn">
  <div class="tab-panel-head"><h2>Top Host Cards</h2><div class="muted">The top 10 hosts are ranked by exposure, role, and evidence quality. Verification commands stay collapsed by default.</div></div>
  <div class="stack">{top_hosts_html}</div>
</section>
{findings_tab}
{verification_tab}
{scan_details_tab}
</main></body></html>""", encoding="utf-8")
    return report


def tool_versions(outdir: Path) -> dict[str, Any]:
    tools = ["ip", "nmap", "nuclei", "nxc", "codex", "arp", "arp-scan"]
    versions = {}
    for tool in tools:
        path = shutil.which(tool)
        if not path:
            versions[tool] = {"installed": False}
            continue
        cmd = [tool, "--version"] if tool not in {"ip", "arp"} else [tool, "-V"]
        rec = run_command(cmd, outdir, f"version_{tool.replace('-', '_')}", timeout=15)
        versions[tool] = {"installed": True, "path": path, "stdout": rec["stdout_path"], "stderr": rec["stderr_path"], "exit_code": rec["exit_code"]}
    (outdir / "tool-versions.json").write_text(json.dumps(versions, indent=2), encoding="utf-8")
    return versions


def sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    if not args.authorized:
        raise SystemExit("[!] Active scanning requires --authorized or --i-own-this-scope.")
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir = RUN_ROOT / run_id
    outdir.mkdir(parents=True, exist_ok=True)
    info(f"Run directory: {outdir}")
    performance: dict[str, Any] = {"scan_batches": [], "screenshots": []}
    deps = tool_versions(outdir)
    requested_network = parse_requested_network(args.cidr)
    ctx = get_interface_context(args.interface, outdir, requested_network=requested_network)
    ctx = apply_requested_scope(ctx, requested_network)
    write_scope(ctx, outdir)
    info("Detected local scope: " + ", ".join(map(str, ctx["networks"])))
    if os.geteuid() != 0:
        warn("Running without root privileges; ARP discovery and service fingerprints may be limited.")
    hosts = discover_hosts(ctx, outdir, args.dry_run, performance)
    info(f"Discovery: {len(hosts)} live/candidate hosts found")
    quick_scan(hosts, ctx, outdir, args.dry_run, performance)
    dc_candidates = discover_domain_controllers(ctx, hosts, outdir, performance, args.dry_run)
    top_hosts = classify_and_rank(hosts, ctx["gateways"], dc_candidates)
    top_hosts = codex_select_top_hosts(hosts, top_hosts, outdir, args.codex_model, args.codex_reasoning, dc_candidates)
    top_hosts = ensure_required_top_hosts(top_hosts, hosts, dc_candidates)
    write_top_hosts(top_hosts, outdir, ctx, dc_candidates)
    info(f"Prioritization: selected {len(top_hosts)} host(s)")
    deep_scan(top_hosts, hosts, outdir, args.dry_run)
    top_hosts = classify_and_rank(hosts, ctx["gateways"], dc_candidates)
    nuclei = run_nuclei(top_hosts, outdir, args.dry_run)
    nxc_summary = run_nxc(top_hosts, outdir, args.dry_run)
    dc_candidates = discover_domain_controllers(ctx, hosts, outdir, performance, args.dry_run, nxc_outdir=outdir / "nxc")
    top_hosts = classify_and_rank(hosts, ctx["gateways"], dc_candidates)
    top_hosts = ensure_required_top_hosts(top_hosts, hosts, dc_candidates)
    write_top_hosts(top_hosts, outdir, ctx, dc_candidates)
    screenshots = capture_web_screenshots(top_hosts, outdir, args.dry_run, performance)
    screenshot_summary = embed_screenshots(top_hosts, outdir)
    write_top_hosts(top_hosts, outdir, ctx, dc_candidates)
    findings = build_findings(top_hosts, nuclei, nxc_summary)
    performance_summary = aggregate_performance(outdir, performance)
    final = {
        "run_id": run_id,
        "authorization": {"acknowledged": True},
        "codex": {"model": args.codex_model, "reasoning_profile": args.codex_reasoning, "reasoning_flag_supported": False},
        "context": {
            "interface": ctx["interface"],
            "addresses": ctx["addresses"],
            "candidate_networks": [str(n) for n in ctx.get("candidate_networks", [])],
            "networks": [str(n) for n in ctx["networks"]],
            "validated_networks": [str(n) for n in ctx.get("validated_networks", ctx["networks"])],
            "gateways": ctx["gateways"],
            "route_overlap_warnings": ctx.get("route_overlap_warnings", []),
            "route_get_samples": ctx.get("route_get_samples", []),
            "route_excluded_networks": ctx.get("route_excluded_networks", []),
        },
        "hosts": [host_to_dict(h) for h in hosts.values()],
        "top_hosts": [host_to_dict(h) for h in top_hosts],
        "findings": findings,
        "nxc": nxc_summary,
        "domain_controllers": [dc_candidates[ip] for ip in dc_candidates],
        "screenshots": screenshots,
        "screenshot_summary": screenshot_summary,
        "performance": performance_summary,
    }
    write_json_file(outdir / "scan-data.json", final)
    report = render_report(outdir, ctx, hosts, top_hosts, findings, deps, final["codex"], nxc_summary, dc_candidates, performance_summary, screenshot_summary)
    info(f"HTML report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
