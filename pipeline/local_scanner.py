#!/usr/bin/env python3
from __future__ import annotations

import argparse
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
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RUN_ROOT = ROOT / "runs"
MAX_ACTIVE_IPV4_ADDRESSES = 65536
MAX_TOP_HOSTS = 10
FRITZBOX_IP = "192.168.178.1"
FAST_PORTS = "21,22,25,53,80,88,110,111,135,139,143,389,443,445,465,587,636,993,995,1433,1521,2049,2375,2376,3000,3306,3389,5000,5432,5601,5900-5909,5985,5986,6379,8000,8080,8443,9200,9300"
DISCOVERY_TCP_PORTS = "53,88,135,139,389,445,464,593,636,3268,3269,5985"
SAFE_NUCLEI_TAGS = "exposure,misconfig,panel,tech,ssl,tls,http"
SAFE_NUCLEI_SEVERITIES = "info,low,medium,high"
WEB_PORTS = {80, 443, 8000, 8080, 8443, 9443, 5000, 5601, 9200}
HIGH_IMPACT_PORTS = {21, 22, 23, 53, 88, 111, 135, 139, 389, 443, 445, 636, 1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 9300}
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
    dc_confidence: str = "low"
    dc_evidence: list[str] = field(default_factory=list)
    screenshot_path: str = ""


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
    route_get_samples: list[dict[str, Any]] = []
    overlap_warnings: list[dict[str, Any]] = []
    excluded_networks: list[str] = []
    validated: list[ipaddress.IPv4Network] = []
    main_by_network: dict[str, list[RouteEntry]] = {}
    for entry in route_main_entries:
        if isinstance(entry.network, ipaddress.IPv4Network):
            main_by_network.setdefault(str(entry.network), []).append(entry)
    for network in candidate_networks:
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
    if requested_network is not None:
        candidate_networks = [network for network in candidate_networks if network == requested_network]
        validated = [network for network in validated if network == requested_network]
        excluded_networks = [reason for reason in excluded_networks if str(requested_network) in reason]
        if str(requested_network) not in [str(net) for net in candidate_networks]:
            excluded_networks.append(f"{requested_network} excluded: not derived from interface routes or addresses")
    return RouteScope(
        interface=iface,
        requested_network=str(requested_network) if requested_network is not None else "",
        addresses=[],
        candidate_networks=sorted(candidate_networks, key=lambda n: (int(n.network_address), n.prefixlen)),
        validated_networks=sorted(dict.fromkeys(validated), key=lambda n: (int(n.network_address), n.prefixlen)),
        excluded_networks=excluded_networks,
        overlap_warnings=overlap_warnings,
        route_get_samples=route_get_samples,
        route_text={},
        route_entries=route_dev_entries + route_main_entries,
    )


def get_interface_context(iface: str, outdir: Path) -> dict[str, Any]:
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
    scope = validate_route_scope(iface, addr_data, route_dev_entries, route_main_entries, outdir)
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
        "candidate_networks": ctx.get("candidate_networks", [str(n) for n in ctx["networks"]]),
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
    host.mac = host.mac or incoming.mac
    host.vendor = host.vendor or incoming.vendor
    host.services.update(incoming.services)
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
        hostnames = node.find("hostnames")
        if hostnames is not None:
            names = [h.get("name", "") for h in hostnames.findall("hostname") if h.get("name")]
            host.hostname = names[0] if names else ""
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


def run_optional_command(cmd: list[str], outdir: Path, name: str, timeout: int = 20) -> tuple[str, dict[str, Any]]:
    if not cmd or not command_exists(cmd[0]):
        return "", {"exit_code": None, "timed_out": False}
    record = run_command(cmd, outdir, name, timeout=timeout)
    text = (outdir / record["stdout_path"]).read_text(encoding="utf-8", errors="replace")
    return text, record


def update_dc_candidate(
    dc_candidates: dict[str, dict[str, Any]],
    host: Host,
    *,
    confidence: str,
    reason: str,
    evidence: list[str],
    source_artifacts: list[str],
    confirmed: bool = False,
) -> dict[str, Any]:
    candidate = dc_candidates.setdefault(host.ip, {
        "ip": host.ip,
        "hostname": host.hostname,
        "evidence": [],
        "confidence": "low",
        "reason": "",
        "confirmed": False,
        "source_artifacts": [],
        "open_ports": [],
        "sources": sorted(host.sources),
        "nmap_evidence": [],
        "nxc_evidence": [],
        "dns_evidence": [],
    })
    candidate["hostname"] = candidate["hostname"] or host.hostname
    candidate["confidence"] = merge_confidence(str(candidate.get("confidence", "low")), confidence)
    candidate["reason"] = reason if not candidate.get("reason") else candidate["reason"]
    candidate["confirmed"] = bool(candidate.get("confirmed")) or confirmed
    candidate["sources"] = sorted(set(candidate.get("sources", [])) | set(host.sources))
    candidate["open_ports"] = sorted(set(candidate.get("open_ports", [])) | set(host.services))
    append_candidate_evidence(candidate, evidence, source_artifacts)
    return candidate


def host_service_evidence(host: Host) -> tuple[int, list[str]]:
    ports = set(host.services)
    evidence = []
    score = 0
    if len(ports & DC_PORTS) >= 3:
        score += 45
        evidence.append("DC-style port mix: " + ", ".join(map(str, sorted(ports & DC_PORTS))))
    if {53, 88, 389, 445}.issubset(ports) or len(ports & {53, 88, 389, 445, 464, 636, 3268, 3269}) >= 4:
        score += 35
        evidence.append("Identity services exposed: DNS/Kerberos/LDAP/SMB/Global Catalog")
    service_names = " ".join(
        " ".join(filter(None, [svc.name, svc.product, svc.version, svc.extrainfo])).lower()
        for svc in host.services.values()
    )
    if any(token in service_names for token in ["active directory", "domain controller", "microsoft dns", "kerberos", "ldap"]):
        score += 20
        evidence.append("Nmap service detection suggests AD, Kerberos, LDAP, or Microsoft DNS")
    if host.hostname and re.search(r"(^|[-_.])(dc|ad|ldap|domain)([-_.]|$)", host.hostname, re.I):
        score += 12
        evidence.append(f"Hostname suggests controller role: {host.hostname}")
    return score, evidence


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
    domain_name = "example.internal"
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
    if not dry_run and command_exists("dig"):
        for label in ("ldap", "kerberos"):
            query = DC_SRV_RECORDS[0].format(domain=domain_name) if label == "ldap" else DC_SRV_RECORDS[1].format(domain=domain_name)
            query_name = f"example.internal_srv_{label}"
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
            for ip in resolved_hosts:
                if ip not in hosts:
                    hosts[ip] = Host(ip=ip, sources={"dns-srv"})
                host = hosts[ip]
                host.sources.add("dns-srv")
                host.dc_candidate = True
                host.dc_confidence = merge_confidence(host.dc_confidence, "medium")
                host.dc_evidence.extend([f"DNS SRV candidate for {domain_name}"] + [f"Resolved from {target}" for target in srv_targets[label]])
                candidate = update_dc_candidate(
                    dc_candidates,
                    host,
                    confidence="medium",
                    reason="DNS SRV records identify a likely domain controller",
                    evidence=[f"DNS SRV {query}", f"Resolved IP {ip} from SRV target"],
                    source_artifacts=artifact_paths,
                    confirmed=True,
                )
                candidate["dns_evidence"].extend([query, *srv_targets[label]])
    elif not dry_run and command_exists("nslookup"):
        for label in ("ldap", "kerberos"):
            query = DC_SRV_RECORDS[0].format(domain=domain_name) if label == "ldap" else DC_SRV_RECORDS[1].format(domain=domain_name)
            query_name = f"example.internal_srv_{label}"
            nslookup_cmd = ["nslookup", "-type=SRV", query]
            if dns_servers:
                nslookup_cmd = ["nslookup", "-type=SRV", query, dns_servers[0]]
            text, record = run_optional_command(nslookup_cmd, outdir, query_name, timeout=25)
            performance.setdefault("commands", []).append(record)
            write_text_file(domain_dir / f"{query_name}.txt", text or "")
            srv_targets[label] = parse_dig_srv_output(text)
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
                        host.dc_candidate = True
                        host.dc_confidence = merge_confidence(host.dc_confidence, "medium")
                        candidate = update_dc_candidate(
                            dc_candidates,
                            host,
                            confidence="medium",
                            reason="DNS SRV records identify a likely domain controller",
                            evidence=[f"DNS SRV {query}", f"Resolved IP {ip} from SRV target"],
                            source_artifacts=[f"domain/{query_name}.txt", f"domain/resolve_{sanitize(target)}.txt"],
                            confirmed=True,
                        )
                        candidate["dns_evidence"].extend([query, target])
    for host in sorted(hosts.values(), key=lambda item: ip_sort_key(item.ip)):
        score, evidence = host_service_evidence(host)
        if score <= 0:
            continue
        if score >= 35:
            confidence = "high" if score >= 50 else "medium"
            host.dc_candidate = True
            host.dc_confidence = merge_confidence(host.dc_confidence, confidence)
            host.dc_evidence.extend(evidence)
            update_dc_candidate(
                dc_candidates,
                host,
                confidence=confidence,
                reason="Service mix suggests a domain controller",
                evidence=evidence,
                source_artifacts=[f"nmap_fast_{sanitize(host.ip)}.xml", f"nmap_deep_{sanitize(host.ip)}.xml"],
                confirmed=score >= 50,
            )
    if nxc_outdir is not None and nxc_outdir.exists():
        nxc_text_parts = []
        for rel in ["jsonl/events.jsonl", "jsonl/findings.jsonl", "reports/markdown-summary.md", "json/summary.json"]:
            path = nxc_outdir / rel
            if path.exists():
                nxc_text_parts.append(f"## {rel}\n{path.read_text(encoding='utf-8', errors='replace')}")
        nxc_text = "\n\n".join(nxc_text_parts)
        if nxc_text:
            write_text_file(domain_dir / "nxc_evidence.txt", nxc_text + "\n")
        for host in hosts.values():
            markers = []
            if host.ip in nxc_text:
                markers.append(f"NXC output references {host.ip}")
            if domain_name in nxc_text:
                markers.append(f"NXC output references {domain_name}")
            if re.search(r"\bldap\b|\bkerberos\b|\bdomain\b", nxc_text, re.I):
                markers.append("NXC output references AD-related protocol evidence")
            if not markers:
                continue
            host.dc_candidate = True
            host.dc_confidence = merge_confidence(host.dc_confidence, "medium")
            if host.ip not in dc_candidates:
                update_dc_candidate(
                    dc_candidates,
                    host,
                    confidence="medium",
                    reason="NXC output suggests domain controller activity",
                    evidence=markers,
                    source_artifacts=["nxc/jsonl/events.jsonl", "nxc/jsonl/findings.jsonl", "nxc/reports/markdown-summary.md"],
                    confirmed=False,
                )
            else:
                candidate = dc_candidates[host.ip]
                candidate["nxc_evidence"].extend(markers)
                append_candidate_evidence(candidate, markers, ["nxc/jsonl/events.jsonl", "nxc/jsonl/findings.jsonl", "nxc/reports/markdown-summary.md"])
                candidate["confidence"] = merge_confidence(candidate["confidence"], "medium")
                host.dc_evidence.extend(markers)
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
            host.dc_confidence = str(candidate.get("confidence", "medium"))
            host.dc_evidence = list(dict.fromkeys(host.dc_evidence + candidate.get("evidence", [])))
            dc_reason = f"Domain controller candidate for example.internal ({host.dc_confidence})"
            add_reason(host, 70 if host.dc_confidence == "high" else 55, dc_reason)
            add_reason(host, 20, "DC evidence: " + "; ".join(candidate.get("evidence", [])[:3]))
            host.role_guess, host.role_confidence = "domain controller candidate", host.dc_confidence
        if host.ip in gateways:
            add_reason(host, 45, "Likely gateway/router/firewall: interface route points to this host")
            host.role_guess, host.role_confidence = "gateway/router/firewall", "high"
        if host.ip == FRITZBOX_IP:
            add_reason(host, 60, "Likely FritzBox/router candidate at 192.168.178.1")
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
        "priority_rules": ["prioritize reachable 192.168.178.1 as likely FritzBox/router", "gateways", "DNS/DHCP/identity", "NAS/storage", "admin protocols", "databases", "web admin", "domain controllers for example.internal"],
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
        "properties": {"hosts": {"type": "array", "items": {"type": "object", "additionalProperties": False, "properties": {"ip": {"type": "string"}, "rationale": {"type": "string"}}}}},
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
    lines = [f"# Top Hosts", "", f"192.168.178.1 status: {status}", ""]
    if dc_candidates:
        lines.append("## Domain Controller Candidates")
        for item in dc_candidates.values():
            lines.append(f"- {item['ip']} {item.get('hostname') or ''}".rstrip())
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
    run_command(cmd, outdir, "nxc_phase", timeout=max(300, len(protocols) * len(top_hosts) * 45))
    summary["ran"] = True
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
                findings.append({
                    "status": "inferred",
                    "severity": "High" if svc.port in {23, 3389, 5985, 5986, 2375, 6379, 9200} else "Medium",
                    "host": host.ip,
                    "title": f"Internal exposure on {svc.port}/{svc.name or 'unknown'}",
                    "evidence": f"{svc.protocol}/{svc.port} {svc.name} {svc.product} {svc.version}".strip(),
                    "confidence": "medium",
                    "cves": [],
                    "recommendation": "Validate business need, restrict management access, and apply vendor hardening. This is not a vulnerability claim by itself.",
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
        findings.append({
            "status": "confirmed",
            "severity": str(info_block.get("severity", "info")).title(),
            "host": str(item.get("host") or item.get("matched-at") or ""),
            "title": str(info_block.get("name", item.get("template-id", "Nuclei finding"))),
            "evidence": str(item.get("template-id", "")),
            "confidence": "medium",
            "cves": cves,
            "recommendation": "Review the raw Nuclei JSONL artifact and validate configuration impact.",
        })
    if nxc_summary.get("ran"):
        findings.append({"status": "informational", "severity": "Info", "host": "n/a", "title": "NXC protocol recon completed", "evidence": ", ".join(nxc_summary.get("selected_protocols", [])), "confidence": "high", "cves": [], "recommendation": "Review nxc/jsonl and nxc/json artifacts for protocol-specific evidence."})
    return findings


def host_to_dict(host: Host) -> dict[str, Any]:
    return {
        "ip": host.ip,
        "hostname": host.hostname,
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
        "dc_confidence": host.dc_confidence,
        "dc_evidence": host.dc_evidence,
        "screenshot_path": host.screenshot_path,
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
    text = " ".join(
        str(finding.get(key, ""))
        for key in ["host", "title", "evidence", "recommendation"]
    )
    return host.ip in text or (host.hostname and host.hostname in text)


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


def host_relevant_cves(findings: list[dict[str, Any]], host: Host) -> list[str]:
    cves = set()
    for item in host_findings(findings, host):
        for cve in item.get("cves", []) or []:
            if isinstance(cve, str) and cve.upper().startswith("CVE-"):
                cves.add(cve.upper())
    return sorted(cves)


def host_verification_commands(host: Host, dc_candidates: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    commands: list[dict[str, str]] = []
    seen = set()
    for svc in sorted(host.services.values(), key=lambda item: (item.port, item.name)):
        if svc.port in WEB_PORTS:
            url = service_url(host.ip, svc.port)
            command = f"curl -k -I --connect-timeout 5 --max-time 10 {shlex.quote(url)}"
            label = f"Confirm web exposure on {svc.port}/{svc.name or 'http'}"
            timeout = "10s"
        else:
            command = f"nc -vz -w 3 {shlex.quote(host.ip)} {svc.port}"
            label = f"Confirm open port {svc.port}/{svc.name or 'tcp'}"
            timeout = "3s"
        if command not in seen:
            commands.append({"label": label, "command": command, "timeout": timeout})
            seen.add(command)
    if host.ip in dc_candidates:
        commands.append({"label": "Confirm AD SRV records", "command": "dig _ldap._tcp.dc._msdcs.example.internal SRV", "timeout": "5s"})
        commands.append({"label": "Confirm Kerberos SRV records", "command": "dig _kerberos._tcp.example.internal SRV", "timeout": "5s"})
    return commands[:8]


def render_host_card(host: Host, findings: list[dict[str, Any]], dc_candidates: dict[str, dict[str, Any]]) -> str:
    ports = ", ".join(f"{svc.port}/{svc.name or 'tcp'}" for svc in sorted(host.services.values(), key=lambda item: item.port)) or "none"
    cves = host_relevant_cves(findings, host)
    severity = host_highest_severity(findings, host)
    findings_html = "".join(
        f"<li><span class='badge severity-{severity_class(item.get('severity', 'Info'))}'>{esc(item.get('severity', 'Info'))}</span> {esc(item.get('title', 'Finding'))} <span class='muted'>({esc(item.get('status', 'unknown'))})</span></li>"
        for item in host_findings(findings, host)[:4]
    ) or "<li class='muted'>No host-specific findings recorded.</li>"
    commands = host_verification_commands(host, dc_candidates)
    command_html = "".join(
        f"<li><code>{esc(cmd['command'])}</code><div class='muted'>{esc(cmd['label'])} - timeout {esc(cmd['timeout'])}</div></li>"
        for cmd in commands
    )
    screenshot_html = f"<img src='{esc(host.screenshot_path)}' alt='Screenshot for {esc(host.ip)}'>" if host.screenshot_path else "<div class='muted'>No screenshot available.</div>"
    dc_badge = f"<span class='badge dc'>Domain controller</span>" if host.ip in dc_candidates else ""
    return f"""
<article class="host-card">
  <div class="host-head">
    <div>
      <div class="host-title">{esc(host.hostname or host.ip)}</div>
      <div class="muted mono">{esc(host.ip)} - score {esc(host.score)} - {esc(host.role_guess or 'unknown')}</div>
    </div>
    <div class="badges">
      <span class="badge severity-{severity_class(severity)}">{esc(severity)}</span>
      <span class="badge">{esc(len(host.services))} open ports</span>
      {dc_badge}
    </div>
  </div>
  <div class="host-grid">
    <div class="shot">{screenshot_html}</div>
    <div class="meta">
      <div><strong>Hostname</strong><br>{esc(host.hostname or 'unknown')}</div>
      <div><strong>Open ports</strong><br>{esc(ports)}</div>
      <div><strong>Relevant CVEs</strong><br>{esc(', '.join(cves) if cves else 'none observed')}</div>
      <div><strong>DC evidence</strong><br>{esc('; '.join(host.dc_evidence[:4]) or 'none')}</div>
    </div>
    <div class="findings">
      <strong>Findings</strong>
      <ul>{findings_html}</ul>
    </div>
    <div class="commands">
      <strong>Verification commands</strong>
      <ul>{command_html or "<li class='muted'>No host-specific validation command generated.</li>"}</ul>
    </div>
  </div>
</article>
"""


def render_report(outdir: Path, ctx: dict[str, Any], hosts: dict[str, Host], top_hosts: list[Host], findings: list[dict[str, Any]], deps: dict[str, Any], profile: dict[str, str], nxc_summary: dict[str, Any], dc_candidates: dict[str, dict[str, Any]], performance_summary: dict[str, Any]) -> Path:
    report = outdir / "report.html"
    fritz_status = json.loads((outdir / "top-hosts.json").read_text(encoding="utf-8")).get("fritzbox_status", "unknown")
    validated_networks = ctx.get("validated_networks", ctx.get("networks", []))
    overlap_warnings = ctx.get("route_overlap_warnings", [])
    route_samples = ctx.get("route_get_samples", [])
    dc_in_top = [ip for ip in dc_candidates if ip in {host.ip for host in top_hosts}]
    both_dc_in_top = len(dc_candidates) >= 2 and len(dc_in_top) >= 2
    total_runtime = round(sum(item.get("duration_seconds", 0.0) for item in performance_summary.get("phase_durations", {}).values()), 3)
    severity_counts = {label: 0 for label in ["Critical", "High", "Medium", "Low", "Info"]}
    for item in findings:
        label = str(item.get("severity", "Info")).title()
        if label not in severity_counts:
            label = "Info"
        severity_counts[label] += 1
    prioritized_findings = sorted(findings, key=lambda item: (-severity_rank(item.get("severity", "")), str(item.get("host", ""))))[:5]
    validated_network_pills = "".join(f"<span class='pill'>{esc(net)}</span>" for net in validated_networks) or "<span class='muted'>none</span>"
    management_bullets = "".join(
        f"<li><span class='badge severity-{severity_class(item.get('severity', 'Info'))}'>{esc(item.get('severity', 'Info'))}</span> {esc(item.get('title', 'Finding'))} on <span class='mono'>{esc(item.get('host', 'n/a'))}</span>: {esc(item.get('evidence', ''))}</li>"
        for item in prioritized_findings
    ) or "<li class='muted'>No high-priority findings were produced.</li>"
    finding_rows = "".join(
        f"<tr class='finding-row' data-severity='{severity_class(item.get('severity'))}' data-search='{esc(' '.join(str(item.get(key, '')) for key in ['severity', 'status', 'host', 'title', 'evidence', 'recommendation']))}'><td><span class='badge severity-{severity_class(item.get('severity'))}'>{esc(item.get('severity'))}</span></td><td>{esc(item.get('status'))}</td><td class='mono'>{esc(item.get('host'))}</td><td>{esc(item.get('title'))}</td><td><details><summary>Evidence</summary><pre>{esc(item.get('evidence'))}</pre></details></td><td>{esc(item.get('recommendation'))}</td></tr>"
        for item in findings
    )
    route_warning_html = "".join(
        f"<tr><td>{esc(item.get('network'))}</td><td>{esc(item.get('effective_dev'))}</td><td>{esc(item.get('effective_via') or 'n/a')}</td><td>{esc('; '.join(r.get('dev', '') for r in item.get('competing_routes', [])) or 'none')}</td></tr>"
        for item in overlap_warnings
    ) or "<tr><td colspan='4' class='muted'>No overlapping routes were detected.</td></tr>"
    route_sample_html = "".join(
        f"<tr><td>{esc(item.get('network'))}</td><td>{esc(item.get('representative_ip'))}</td><td>{esc(item.get('effective_dev') or 'unknown')}</td><td><pre>{esc(item.get('stdout') or item.get('stderr'))}</pre></td></tr>"
        for item in route_samples
    ) or "<tr><td colspan='4' class='muted'>No route lookup samples recorded.</td></tr>"
    dc_rows = "".join(
        f"<tr><td>{esc(item.get('ip'))}</td><td>{esc(item.get('hostname') or '')}</td><td>{esc(item.get('confidence'))}</td><td>{esc('yes' if item.get('confirmed') else 'no')}</td><td>{esc(item.get('reason'))}</td><td>{esc(', '.join(map(str, item.get('open_ports', []))) or 'none')}</td><td>{esc('; '.join(item.get('evidence', [])) or 'none')}</td></tr>"
        for item in dc_candidates.values()
    ) or "<tr><td colspan='7' class='muted'>No DC candidates discovered.</td></tr>"
    verification_rows = []
    for host in top_hosts:
        for cmd in host_verification_commands(host, dc_candidates):
            verification_rows.append(f"<tr><td>{esc(host.ip)}</td><td>{esc(host.hostname or '')}</td><td>{esc(cmd['label'])}</td><td>{esc(cmd['timeout'])}</td><td><code>{esc(cmd['command'])}</code></td></tr>")
    verification_html = "".join(verification_rows) or "<tr><td colspan='5' class='muted'>No verification commands generated.</td></tr>"
    timeout_rows = "".join(
        f"<tr><td>{esc(item.get('name'))}</td><td>{esc(item.get('exit_code'))}</td><td>{esc(item.get('timeout_seconds'))}</td><td>{esc(item.get('duration_seconds'))}</td><td>{esc('partial' if item.get('timed_out') or item.get('exit_code') == 124 else 'complete')}</td></tr>"
        for item in performance_summary.get("timeouts", [])
    ) or "<tr><td colspan='5' class='muted'>No timeouts recorded.</td></tr>"
    batch_rows = "".join(
        f"<tr><td>{esc(item.get('phase'))}</td><td>{esc(item.get('network'))}</td><td>{esc(item.get('host_count'))}</td><td>{esc(item.get('duration_seconds'))}</td><td>{esc(item.get('timeout_seconds'))}</td><td>{esc('yes' if item.get('timed_out') else 'no')}</td></tr>"
        for item in performance_summary.get("scan_batches", [])
    ) or "<tr><td colspan='6' class='muted'>No scan batches recorded.</td></tr>"
    phase_rows = "".join(
        f"<tr><td>{esc(phase)}</td><td>{esc(data.get('duration_seconds'))}</td><td>{esc(data.get('timeout_count'))}</td><td>{esc(', '.join(data.get('commands', [])) or 'none')}</td></tr>"
        for phase, data in performance_summary.get("phase_durations", {}).items()
    )
    host_cards = "".join(render_host_card(host, findings, dc_candidates) for host in top_hosts)
    report.write_text(f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#FAFAFA">
<title>C3PO Local Scanner Report</title>
<script>
  (function(){{
    var s = localStorage.getItem('theme');
    if (!s) s = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    document.documentElement.dataset.theme = s;
    document.documentElement.style.colorScheme = s;
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', s === 'dark' ? '#0A0A0A' : '#FAFAFA');
  }})();
</script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Space+Grotesk:wght@500;600;700&display=swap');
:root {{color-scheme: light;--font-sans:"IBM Plex Sans",system-ui,sans-serif;--font-header:"Space Grotesk",system-ui,sans-serif;--font-mono:"JetBrains Mono",monospace;--bg:#FAFAFA;--bg-subtle:#F5F5F5;--ui:#F0F0F0;--ui-hover:#E8E8E8;--line:#EAEAEA;--border:#E0E0E0;--border-hover:#D0D0D0;--ink:#000000;--text:#171717;--surface:#FFFFFF;--muted:#6E6E6E;--accent:#000000;--on-accent:#FFFFFF;--focus-ring:#000000;--sev-crit-bg:#FCE4E4;--sev-crit-bd:#F5C6C7;--sev-crit-fg:#B91212;--sev-high-bg:#FCEEE3;--sev-high-bd:#F6DEC8;--sev-high-fg:#C2410C;--sev-med-bg:#FBF3DD;--sev-med-bd:#F0E4BE;--sev-med-fg:#B07A06;--sev-low-bg:#E6F6EE;--sev-low-bd:#CDEBDA;--sev-low-fg:#0E9E57;--header-bg:rgba(255,255,255,.82);--glass-bg:rgba(255,255,255,.55);--glass-border:rgba(0,0,0,.1);--row-hover:#FAFAFA}}
html[data-theme="dark"] {{color-scheme: dark;--bg:#0A0A0A;--bg-subtle:#111111;--ui:#1A1A1A;--ui-hover:#222222;--line:rgba(255,255,255,.1);--border:rgba(255,255,255,.14);--border-hover:rgba(255,255,255,.22);--ink:#EDEDED;--text:#EDEDED;--surface:#161616;--muted:#A1A1A1;--accent:#EDEDED;--on-accent:#0A0A0A;--focus-ring:#EDEDED;--sev-crit-bg:rgba(229,72,77,.15);--sev-crit-bd:rgba(229,72,77,.25);--sev-crit-fg:#FF6369;--sev-high-bg:rgba(255,128,31,.12);--sev-high-bd:rgba(255,128,31,.22);--sev-high-fg:#FF8B3E;--sev-med-bg:rgba(255,178,36,.12);--sev-med-bd:rgba(255,178,36,.22);--sev-med-fg:#FFB224;--sev-low-bg:rgba(70,167,88,.12);--sev-low-bd:rgba(70,167,88,.22);--sev-low-fg:#46A758;--header-bg:rgba(10,10,10,.82);--glass-bg:rgba(255,255,255,.05);--glass-border:rgba(255,255,255,.12);--row-hover:rgba(255,255,255,.035)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:radial-gradient(circle at 20% -10%,var(--ui),transparent 34rem),linear-gradient(180deg,var(--bg),var(--bg-subtle));color:var(--text);font:14px/1.6 var(--font-sans)}}header{{position:sticky;top:0;z-index:10;background:var(--header-bg);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}}.header-inner,main{{max-width:1000px;margin:0 auto;padding:2rem 1.5rem}}.header-inner{{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding-top:1rem;padding-bottom:1rem}}h1,h2,h3,.host-title,.summary-tile strong,.button{{font-family:var(--font-header)}}h1{{margin:0;font-size:clamp(1.6rem,4vw,2.7rem);letter-spacing:-.04em;color:var(--ink)}}h2{{margin:0 0 1rem;font-size:1.35rem;letter-spacing:-.025em}}h3{{margin:1.4rem 0 .7rem;font-size:1rem}}p{{margin:.4rem 0 0}}main{{display:grid;gap:1rem}}section,.host-card,.panel,.summary-tile{{background:var(--surface);border:1px solid var(--border);border-radius:8px}}section{{padding:1.25rem;box-shadow:0 18px 50px rgba(0,0,0,.04)}}.summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem}}.summary-tile{{padding:1.25rem;transition:border-color .2s ease-in-out;cursor:pointer;text-align:left;color:var(--text)}}.summary-tile:hover,.summary-tile.active{{border-color:var(--border-hover)}}.summary-tile strong{{display:block;font-size:2rem;line-height:1.1;margin-top:.35rem}}.summary-tile.static{{cursor:default}}.muted{{color:var(--muted)}}.mono,code,pre{{font-family:var(--font-mono)}}.button,.theme-toggle,.search-box button{{background:var(--accent);color:var(--on-accent);border:none;border-radius:6px;padding:.5rem 1.2rem;font-family:var(--font-header);font-weight:600;cursor:pointer;transition:opacity .2s}}.button:hover,.theme-toggle:hover,.search-box button:hover{{opacity:.78}}.search-box{{display:flex;align-items:center;border:1px solid var(--border);border-radius:8px;background:var(--surface);padding:.25rem .25rem .25rem 1rem;margin-bottom:1rem}}.search-box input{{border:none;outline:none;background:transparent;color:var(--text);font-family:var(--font-sans);width:100%;min-width:0}}table{{width:100%;border-collapse:collapse}}th,td{{border-bottom:1px solid var(--line);padding:1rem .75rem;text-align:left;vertical-align:top}}th{{font-family:var(--font-header);font-weight:600;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}}tr:hover{{background-color:var(--row-hover)}}code{{display:block;white-space:pre-wrap;background:var(--bg-subtle);border:1px solid var(--line);border-radius:6px;padding:.65rem;overflow-x:auto;color:var(--text);font-size:13.5px}}pre{{margin:0;white-space:pre-wrap;background:var(--bg-subtle);border:1px solid var(--line);border-radius:6px;padding:1rem;overflow-x:auto;color:var(--text);font-size:13.5px}}details summary{{cursor:pointer;font-family:var(--font-header);font-weight:600;color:var(--ink)}}details pre{{margin-top:.65rem}}.badge{{display:inline-flex;align-items:center;justify-content:center;padding:2px 8px;border-radius:4px;font-family:var(--font-sans);font-size:12px;font-weight:600;text-transform:uppercase;background:var(--ui);border:1px solid var(--border);color:var(--text)}}.severity-critical{{background:var(--sev-crit-bg);border-color:var(--sev-crit-bd);color:var(--sev-crit-fg)}}.severity-high{{background:var(--sev-high-bg);border-color:var(--sev-high-bd);color:var(--sev-high-fg)}}.severity-medium{{background:var(--sev-med-bg);border-color:var(--sev-med-bd);color:var(--sev-med-fg)}}.severity-low{{background:var(--sev-low-bg);border-color:var(--sev-low-bd);color:var(--sev-low-fg)}}.severity-info{{background:var(--ui);border-color:var(--border);color:var(--muted)}}.dc{{background:var(--glass-bg);border-color:var(--glass-border)}}.pill{{display:inline-flex;padding:4px 8px;border-radius:999px;background:var(--ui);border:1px solid var(--border);margin:0 6px 6px 0;font-family:var(--font-mono);font-size:12px}}.section-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1rem}}.panel{{padding:1rem;background:var(--glass-bg);border-color:var(--glass-border)}}.note{{background:var(--glass-bg);border:1px solid var(--glass-border);border-radius:8px;padding:1rem}}.stack{{display:grid;gap:1rem}}.host-card{{padding:1.25rem;transition:border-color .2s ease-in-out}}.host-card:hover{{border-color:var(--border-hover)}}.host-head{{display:flex;justify-content:space-between;gap:1rem;align-items:flex-start;margin-bottom:1rem}}.host-title{{font-size:1.25rem;font-weight:700;letter-spacing:-.025em}}.badges{{display:flex;gap:.5rem;flex-wrap:wrap;justify-content:flex-end}}.host-grid{{display:grid;grid-template-columns:1.1fr .9fr 1fr 1fr;gap:1rem}}.shot img{{width:100%;border-radius:8px;border:1px solid var(--border);background:var(--bg-subtle);aspect-ratio:16/10;object-fit:cover}}.findings ul,.commands ul{{margin:.6rem 0 0 1rem;padding:0}}.findings li,.commands li{{margin:0 0 .6rem}}.table-wrap{{overflow-x:auto}}@media (max-width:820px){{.header-inner{{align-items:flex-start;flex-direction:column}}.host-grid{{grid-template-columns:1fr}}th,td{{padding:.8rem .55rem}}}}
</style></head><body><header><div class="header-inner"><div><h1>C3PO Local Scanner Report</h1><p class="muted">Authorized internal scan via <span class="mono">{esc(ctx['interface'])}</span> - run <span class="mono">{esc(outdir.name)}</span></p></div><button class="theme-toggle" id="themeToggle" type="button">Toggle theme</button></div></header><main>
<section><h2>Management Summary</h2><div class="summary-grid"><button class="summary-tile" type="button" data-filter="critical"><span class="muted">Critical</span><strong>{severity_counts['Critical']}</strong></button><button class="summary-tile" type="button" data-filter="high"><span class="muted">High</span><strong>{severity_counts['High']}</strong></button><button class="summary-tile" type="button" data-filter="medium"><span class="muted">Medium</span><strong>{severity_counts['Medium']}</strong></button><button class="summary-tile" type="button" data-filter="low"><span class="muted">Low</span><strong>{severity_counts['Low']}</strong></button><div class="summary-tile static"><span class="muted">Domain controllers in top 10</span><strong>{'yes' if both_dc_in_top else 'no'}</strong></div><div class="summary-tile static"><span class="muted">Route warnings</span><strong>{len(overlap_warnings)}</strong></div><div class="summary-tile static"><span class="muted">Runtime</span><strong>{total_runtime}s</strong></div></div><div class="note" style="margin-top:1rem"><strong>Priority findings</strong><ul>{management_bullets}</ul></div></section>
<section><h2>Routing and Scope</h2><div class="section-grid"><div class="panel"><strong>Selected interface</strong><div>{esc(ctx['interface'])}</div><div class="muted">Codex profile: {esc(profile)}</div></div><div class="panel"><strong>Validated tun0 networks</strong><div>{validated_network_pills}</div></div><div class="panel"><strong>Excluded routes</strong><pre>{esc('; '.join(ctx.get('route_excluded_networks', [])) or 'none')}</pre></div><div class="panel"><strong>Overlap warnings</strong><pre>{esc('; '.join(item.get('network', '') + ' -> ' + (item.get('effective_dev') or 'unknown') for item in overlap_warnings) or 'none')}</pre></div></div><h3>Route validation evidence</h3><table><tr><th>Network</th><th>Representative IP</th><th>Effective dev</th><th>Route output</th></tr>{route_sample_html}</table><h3>Overlap details</h3><table><tr><th>Network</th><th>Effective dev</th><th>Via</th><th>Competing devs</th></tr>{route_warning_html}</table><h3>Domain Controller Candidates</h3><table><tr><th>IP</th><th>Hostname</th><th>Confidence</th><th>Confirmed</th><th>Reason</th><th>Ports</th><th>Evidence</th></tr>{dc_rows}</table><p class="muted">Detected DNS domain: example.internal. Both DCs included in top 10: { 'yes' if both_dc_in_top else 'no' }.</p></section>
<section><h2>Tool Versions</h2><pre>{esc(json.dumps(deps, indent=2))}</pre></section>
<section><h2>Top 10 Host Cards</h2><div class="stack">{host_cards or '<div class="muted">No top hosts available.</div>'}</div></section>
<section><h2>Findings</h2><form class="search-box" id="findingSearch"><input id="findingQuery" type="search" placeholder="Search findings by host, service, evidence, or recommendation" autocomplete="off"><button type="submit">Search</button></form><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Status</th><th>Host</th><th>Finding</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody id="findingsBody">{finding_rows or '<tr><td colspan="6" class="muted">No findings generated.</td></tr>'}</tbody></table></div></section>
<section><h2>Verification Commands, Timeouts, and Partial Results</h2><div class="note">Commands in this section are limited to the top 10 hosts and are intended to confirm the findings already shown above.</div><h3>Verification commands</h3><table><tr><th>Host</th><th>Hostname</th><th>Purpose</th><th>Timeout</th><th>Command</th></tr>{verification_html}</table><h3>Timeouts and partial results</h3><table><tr><th>Command</th><th>Exit</th><th>Timeout</th><th>Duration</th><th>Status</th></tr>{timeout_rows}</table></section>
<section><h2>Performance</h2><table><tr><th>Phase</th><th>Duration</th><th>Timeouts</th><th>Commands</th></tr>{phase_rows or '<tr><td colspan="4" class="muted">No phase timing data recorded.</td></tr>'}</table><h3>Scan batches</h3><table><tr><th>Phase</th><th>Network</th><th>Hosts</th><th>Duration</th><th>Timeout</th><th>Timed out</th></tr>{batch_rows}</table></section>
<section><h2>Nmap, Nuclei, and NXC Summary</h2><p>Nmap artifacts, Nuclei JSONL, and NXC structured outputs are stored beside this report. NXC selected protocols: {esc(', '.join(nxc_summary.get('selected_protocols', [])) or 'none')}. Screenshots: {esc('yes' if performance_summary.get('screenshots') else 'no')}.</p></section>
<section><h2>Assumptions and Limitations</h2><p>Results depend on local privileges, host firewall behavior, Wi-Fi client isolation, optional tool availability, and scan timing. The scanner does not run brute force, credential dumping, exploit modules, coercion, password changes, or state-changing tests.</p></section>
<script>
(function(){{
  var activeSeverity = '';
  var rows = Array.prototype.slice.call(document.querySelectorAll('.finding-row'));
  var input = document.getElementById('findingQuery');
  var form = document.getElementById('findingSearch');
  var meta = document.querySelector('meta[name="theme-color"]');
  function applyFilters(){{
    var query = (input && input.value ? input.value : '').trim().toLowerCase();
    rows.forEach(function(row){{
      var matchesText = !query || (row.dataset.search || row.textContent).toLowerCase().indexOf(query) !== -1;
      var matchesSeverity = !activeSeverity || row.dataset.severity === activeSeverity;
      row.style.display = matchesText && matchesSeverity ? '' : 'none';
    }});
  }}
  if (input) input.addEventListener('keyup', applyFilters);
  if (form) form.addEventListener('submit', function(event){{ event.preventDefault(); applyFilters(); }});
  document.querySelectorAll('[data-filter]').forEach(function(card){{
    card.addEventListener('click', function(){{
      activeSeverity = activeSeverity === card.dataset.filter ? '' : card.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach(function(item){{ item.classList.toggle('active', item === card && activeSeverity); }});
      applyFilters();
    }});
  }});
  var themeToggle = document.getElementById('themeToggle');
  if (themeToggle) themeToggle.addEventListener('click', function(){{
    var nextTheme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nextTheme;
    document.documentElement.style.colorScheme = nextTheme;
    localStorage.setItem('theme', nextTheme);
    if (meta) meta.setAttribute('content', nextTheme === 'dark' ? '#0A0A0A' : '#FAFAFA');
  }});
}})();
</script>
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
    ctx = get_interface_context(args.interface, outdir)
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
    findings = build_findings(top_hosts, nuclei, nxc_summary)
    performance_summary = aggregate_performance(outdir, performance)
    final = {
        "run_id": run_id,
        "authorization": {"acknowledged": True},
        "codex": {"model": args.codex_model, "reasoning_profile": args.codex_reasoning, "reasoning_flag_supported": False},
        "context": {
            "interface": ctx["interface"],
            "addresses": ctx["addresses"],
            "candidate_networks": ctx.get("candidate_networks", []),
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
        "performance": performance_summary,
    }
    write_json_file(outdir / "scan-data.json", final)
    report = render_report(outdir, ctx, hosts, top_hosts, findings, deps, final["codex"], nxc_summary, dc_candidates, performance_summary)
    info(f"HTML report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
