#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REPORT_ROOT = ROOT / "reports"
MAX_ACTIVE_IPV4_ADDRESSES = 4096
MAX_TOP_HOSTS = 10

EXCLUDED_IPV4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("255.255.255.255/32"),
]

SAFE_NUCLEI_TAGS = "exposure,misconfig,panel,tech,ssl,tls,http"
SAFE_NUCLEI_SEVERITIES = "info,low,medium,high"
WEB_PORTS = {80, 443, 8000, 8006, 8080, 8443, 8888, 9000, 9090, 9443, 10000}
HIGH_IMPACT_PORTS = {
    21, 22, 23, 53, 88, 135, 137, 138, 139, 161, 389, 443, 445, 636, 873, 1433,
    1521, 2049, 3268, 3269, 3306, 3389, 5432, 5480, 5900, 5985, 5986, 6379,
    8000, 8006, 8080, 8443, 8888, 9200, 9300, 9443, 10000, 27017,
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

    @property
    def label(self) -> str:
        bits = [self.name or "unknown"]
        product = " ".join(x for x in [self.product, self.version, self.extrainfo] if x)
        if product:
            bits.append(product)
        return " - ".join(bits)


@dataclass
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    sources: set[str] = field(default_factory=set)
    services: dict[int, Service] = field(default_factory=dict)
    role_indicators: list[str] = field(default_factory=list)
    score: int = 0
    ranking_reasons: list[str] = field(default_factory=list)
    deep_scanned: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, str]] = field(default_factory=list)


def run(cmd: list[str], timeout: int = 60, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=check)


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def info(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def load_json_command(cmd: list[str], timeout: int = 20) -> Any:
    result = run(cmd, timeout=timeout)
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout)


def ipv4_scope_allowed(net: ipaddress.IPv4Network) -> bool:
    if net.prefixlen == 0 or net.num_addresses > MAX_ACTIVE_IPV4_ADDRESSES:
        return net.is_private and not any(net.subnet_of(excluded) or net == excluded for excluded in EXCLUDED_IPV4)
    if not (net.is_private or net.is_link_local):
        return False
    return not any(net.subnet_of(excluded) or net == excluded for excluded in EXCLUDED_IPV4)


def ipv4_active_allowed(net: ipaddress.IPv4Network) -> bool:
    return ipv4_scope_allowed(net) and net.num_addresses <= MAX_ACTIVE_IPV4_ADDRESSES


def ipv6_allowed(net: ipaddress.IPv6Network) -> bool:
    return net.prefixlen >= 64 and (net.is_private or net.is_link_local) and not (
        net.is_loopback or net.is_multicast or net.is_unspecified
    )


def safe_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 4:
        return (ip.is_private or ip.is_link_local) and not any(ip in excluded for excluded in EXCLUDED_IPV4)
    return (ip.is_private or ip.is_link_local) and not (ip.is_loopback or ip.is_multicast or ip.is_unspecified)


def ip_sort_key(value: str) -> tuple[int, tuple[int, ...], str]:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return (ip.version, tuple(ip.packed), value)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local internal attack-surface scanner")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to scan, for example eth0")
    parser.add_argument("--verbose", action="store_true", help="Print verbose scanner output")
    parser.add_argument("--dry-run", action="store_true", help="Validate local scope and render a report without active scans")
    return parser.parse_args()


def get_interface_context(iface: str) -> dict[str, Any]:
    if not command_exists("ip"):
        raise SystemExit("[!] Missing required command: ip")

    links = load_json_command(["ip", "-j", "link", "show", "dev", iface])
    if not links:
        raise SystemExit(f"[!] Interface does not exist or cannot be read: {iface}")
    link = links[0]
    if "UP" not in link.get("flags", []):
        warn(f"Interface {iface} is not marked UP; discovery may be limited.")

    addr_data = load_json_command(["ip", "-j", "addr", "show", "dev", iface]) or []
    route4 = run(["ip", "route", "show", "dev", iface], timeout=20)
    route6 = run(["ip", "-6", "route", "show", "dev", iface], timeout=20)
    neigh = run(["ip", "neigh", "show", "dev", iface], timeout=20)
    resolvectl = run(["resolvectl", "status"], timeout=20) if command_exists("resolvectl") else None

    networks: list[ipaddress._BaseNetwork] = []
    addresses: list[str] = []
    for item in addr_data:
        for addr in item.get("addr_info", []):
            local = addr.get("local")
            prefix = addr.get("prefixlen")
            family = addr.get("family")
            if not local or prefix is None:
                continue
            try:
                net = ipaddress.ip_network(f"{local}/{prefix}", strict=False)
            except ValueError:
                continue
            addresses.append(f"{local}/{prefix}")
            if family == "inet" and isinstance(net, ipaddress.IPv4Network) and ipv4_scope_allowed(net):
                networks.append(net)
            elif family == "inet6" and isinstance(net, ipaddress.IPv6Network) and ipv6_allowed(net):
                networks.append(net)

    gateways = []
    for line in route4.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "default":
            if "via" in parts:
                gateways.append(parts[parts.index("via") + 1])
            continue
        try:
            net = ipaddress.ip_network(parts[0], strict=False)
        except (ValueError, IndexError):
            continue
        if isinstance(net, ipaddress.IPv4Network) and ipv4_scope_allowed(net) and net not in networks:
            networks.append(net)

    for line in route6.stdout.splitlines():
        parts = line.split()
        if not parts or parts[0] in {"default", "::/0"}:
            continue
        try:
            net = ipaddress.ip_network(parts[0], strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv6Network) and ipv6_allowed(net) and net not in networks:
            networks.append(net)

    if not networks:
        raise SystemExit(f"[!] Interface {iface} has no safe local/internal scope to scan.")

    skipped_routes = []
    for line in route4.stdout.splitlines() + route6.stdout.splitlines():
        target = line.split()[0] if line.split() else ""
        if target in {"default", "0.0.0.0/0", "::/0"}:
            skipped_routes.append(line)
            continue
        try:
            net = ipaddress.ip_network(target, strict=False)
            if net.version == 4 and (net.prefixlen == 0 or (net.num_addresses > MAX_ACTIVE_IPV4_ADDRESSES and not net.is_private)):
                skipped_routes.append(line)
            elif net.version == 4 and net.num_addresses > MAX_ACTIVE_IPV4_ADDRESSES:
                skipped_routes.append(f"{line} [active sweep skipped: route is broader than {MAX_ACTIVE_IPV4_ADDRESSES} addresses]")
        except ValueError:
            pass

    return {
        "interface": iface,
        "link": link,
        "addresses": addresses,
        "networks": sorted(networks, key=lambda n: (n.version, str(n))),
        "gateways": [g for g in gateways if safe_ip(g)],
        "route4": route4.stdout,
        "route6": route6.stdout,
        "neigh": neigh.stdout,
        "resolvectl": resolvectl.stdout if resolvectl else "",
        "skipped_routes": skipped_routes,
    }


def parse_neighbors(text: str) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not safe_ip(parts[0]):
            continue
        ip = parts[0].split("%", 1)[0]
        host = hosts.setdefault(ip, Host(ip=ip))
        host.sources.add("neighbor-cache")
        if "lladdr" in parts:
            host.mac = parts[parts.index("lladdr") + 1]
        if "FAILED" in parts or "INCOMPLETE" in parts:
            continue
    return hosts


def discover_docker_hosts(ctx: dict[str, Any]) -> dict[str, Host]:
    hosts: dict[str, Host] = {}
    if not command_exists("docker"):
        return hosts
    try:
        networks_result = run(["docker", "network", "ls", "-q"], timeout=20)
    except Exception:
        return hosts
    network_ids = [line.strip() for line in networks_result.stdout.splitlines() if line.strip()]
    if not network_ids:
        return hosts
    try:
        inspect_result = run(["docker", "network", "inspect", *network_ids], timeout=60)
        networks = json.loads(inspect_result.stdout) if inspect_result.stdout.strip() else []
    except Exception:
        return hosts

    scope_networks = ctx.get("networks", [])
    iface = ctx.get("interface", "")
    for network in networks:
        options = network.get("Options") or {}
        bridge_name = options.get("com.docker.network.bridge.name")
        if bridge_name and bridge_name != iface:
            continue
        containers = network.get("Containers") or {}
        for container in containers.values():
            raw_ip = str(container.get("IPv4Address", "")).split("/", 1)[0]
            if not raw_ip or not safe_ip(raw_ip):
                continue
            ip_obj = ipaddress.ip_address(raw_ip)
            if scope_networks and not any(ip_obj in net for net in scope_networks):
                continue
            host = Host(
                ip=raw_ip,
                mac=str(container.get("MacAddress", "")),
                hostname=str(container.get("Name", "")),
            )
            host.sources.add("docker-metadata")
            hosts[raw_ip] = host
    return hosts


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


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
        warn(f"Could not parse nmap XML artifact: {path}")
        return hosts
    for node in root.findall("host"):
        status = node.find("status")
        if status is not None and status.get("state") not in {"up", None}:
            continue
        ip = ""
        mac = ""
        vendor = ""
        for address in node.findall("address"):
            if address.get("addrtype") in {"ipv4", "ipv6"} and safe_ip(address.get("addr", "")):
                ip = address.get("addr", "")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr", "")
                vendor = address.get("vendor", "")
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
                service_node = port_node.find("service")
                service = Service(
                    port=int(port_node.get("portid", "0")),
                    protocol=port_node.get("protocol", "tcp"),
                    state="open",
                )
                if service_node is not None:
                    service.name = service_node.get("name", "")
                    service.product = service_node.get("product", "")
                    service.version = service_node.get("version", "")
                    service.extrainfo = service_node.get("extrainfo", "")
                host.services[service.port] = service
        hosts[ip] = host
    return hosts


def discover_hosts(ctx: dict[str, Any], outdir: Path, dry_run: bool) -> dict[str, Host]:
    hosts = parse_neighbors(ctx["neigh"])
    for host in discover_docker_hosts(ctx).values():
        merge_host(hosts, host)
    for gateway in ctx["gateways"]:
        host = hosts.setdefault(gateway, Host(ip=gateway))
        host.sources.add("gateway")

    if command_exists("arp"):
        arp = run(["arp", "-an"], timeout=20)
        for match in re.finditer(r"\(([^)]+)\)\s+at\s+([0-9a-fA-F:]{11,17})", arp.stdout):
            ip, mac = match.groups()
            if safe_ip(ip):
                merge_host(hosts, Host(ip=ip, mac=mac, sources={"arp-cache"}))

    if dry_run:
        return hosts

    if command_exists("arp-scan") and os.geteuid() == 0:
        for net in ctx["networks"]:
            if net.version == 4 and ipv4_active_allowed(net):
                result = run(["arp-scan", "--interface", ctx["interface"], str(net)], timeout=180)
                for line in result.stdout.splitlines():
                    fields = line.split()
                    if fields and safe_ip(fields[0]):
                        incoming = Host(ip=fields[0], mac=fields[1] if len(fields) > 1 else "")
                        incoming.vendor = " ".join(fields[2:]) if len(fields) > 2 else ""
                        incoming.sources.add("arp-scan")
                        merge_host(hosts, incoming)

    if command_exists("nmap"):
        scan_targets = [str(n) for n in ctx["networks"] if n.version == 4 and ipv4_active_allowed(n)]
        if scan_targets:
            discovery_xml = outdir / "nmap_discovery.xml"
            cmd = ["nmap", "-sn", "-T3", "-oX", str(discovery_xml), *scan_targets]
            (outdir / "nmap_discovery_command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
            info("Discovery: running bounded nmap ping scan")
            run(cmd, timeout=900)
            for host in parse_nmap_xml(discovery_xml).values():
                host.sources.add("nmap-ping")
                merge_host(hosts, host)
    else:
        warn("nmap not installed; active host discovery and port scanning will be limited.")

    for host in hosts.values():
        host.hostname = host.hostname or reverse_dns(host.ip)
    return dict(sorted(hosts.items(), key=lambda item: ip_sort_key(item[0])))


def quick_scan(hosts: dict[str, Host], outdir: Path, dry_run: bool) -> None:
    if dry_run or not hosts or not command_exists("nmap"):
        return
    target_file = outdir / "quick_targets.txt"
    target_file.write_text("\n".join(hosts.keys()) + "\n", encoding="utf-8")
    quick_xml = outdir / "nmap_quick.xml"
    cmd = ["nmap", "-Pn", "-T3", "--top-ports", "100", "--open", "-oX", str(quick_xml), "-iL", str(target_file)]
    (outdir / "nmap_quick_command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
    info(f"Quick scan: scanning {len(hosts)} discovered hosts")
    run(cmd, timeout=max(600, len(hosts) * 20))
    for host in parse_nmap_xml(quick_xml).values():
        host.sources.add("quick-scan")
        merge_host(hosts, host)


def add_reason(host: Host, score: int, reason: str) -> None:
    host.score += score
    if reason not in host.ranking_reasons:
        host.ranking_reasons.append(reason)


def classify_and_rank(hosts: dict[str, Host], gateways: list[str]) -> list[Host]:
    for host in hosts.values():
        ports = set(host.services)
        host.score = 0
        host.ranking_reasons = []
        if host.ip in gateways:
            add_reason(host, 35, "Likely network gateway: interface route points to this host")
        if {88, 389, 445}.issubset(ports) or ({53, 88, 389, 445} & ports and len({53, 88, 389, 445} & ports) >= 3):
            add_reason(host, 45, "Likely domain controller or identity server: Kerberos, LDAP, SMB, or DNS exposed")
        if ports & {53}:
            add_reason(host, 12, "DNS service exposed")
        if ports & {445, 2049, 873}:
            add_reason(host, 20, "Potential file, backup, or storage service exposed")
        if ports & {3389, 5985, 5986, 22, 23, 10000}:
            add_reason(host, 20, "Remote administration service exposed")
        if ports & WEB_PORTS:
            add_reason(host, 18, "HTTP/HTTPS or management web interface exposed")
        if ports & {1433, 1521, 3306, 5432, 6379, 9200, 9300, 27017}:
            add_reason(host, 25, "Database or data service exposed")
        if ports & {8006, 5480, 9090, 9443}:
            add_reason(host, 25, "Virtualization or infrastructure management port exposed")
        if ports & {161}:
            add_reason(host, 16, "SNMP service exposed")
        legacy = ports & {21, 23}
        if legacy:
            add_reason(host, 18, f"Legacy cleartext service exposed: {', '.join(map(str, sorted(legacy)))}")
        high = ports & HIGH_IMPACT_PORTS
        if high:
            add_reason(host, min(30, len(high) * 5), f"High-impact service exposure on ports: {', '.join(map(str, sorted(high)))}")
        if len(ports) >= 8:
            add_reason(host, 20, f"High exposure: {len(ports)} open TCP services")
        elif len(ports) >= 4:
            add_reason(host, 10, f"Moderate exposure: {len(ports)} open TCP services")
        if host.vendor:
            vendor_lower = host.vendor.lower()
            if any(token in vendor_lower for token in ["cisco", "juniper", "fortinet", "palo alto", "ubiquiti", "mikrotik"]):
                add_reason(host, 25, f"Network appliance vendor fingerprint: {host.vendor}")
            if any(token in vendor_lower for token in ["synology", "qnap", "netgear", "western digital"]):
                add_reason(host, 22, f"Potential NAS/storage vendor fingerprint: {host.vendor}")
            if any(token in vendor_lower for token in ["vmware", "proxmox"]):
                add_reason(host, 22, f"Virtualization vendor fingerprint: {host.vendor}")
        if not host.ranking_reasons:
            add_reason(host, 1 if host.sources else 0, "Live host discovered with no high-impact service evidence")
        host.role_indicators = host.ranking_reasons[:]
    return sorted(hosts.values(), key=lambda h: (-h.score, -len(h.services), ip_sort_key(h.ip)))[:MAX_TOP_HOSTS]


def deep_scan(top_hosts: list[Host], hosts: dict[str, Host], outdir: Path, dry_run: bool) -> None:
    if dry_run or not top_hosts or not command_exists("nmap"):
        return
    info(f"Deep scan: scanning top {len(top_hosts)} prioritized hosts")
    for host in top_hosts:
        deep_xml = outdir / f"nmap_deep_{sanitize(host.ip)}.xml"
        cmd = ["nmap", "-Pn", "-sV", "-sC", "-T3", "--open", "-oX", str(deep_xml), host.ip]
        (outdir / f"nmap_deep_{sanitize(host.ip)}_command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        run(cmd, timeout=900)
        parsed = parse_nmap_xml(deep_xml)
        if host.ip in parsed:
            parsed[host.ip].sources.add("deep-scan")
            merge_host(hosts, parsed[host.ip]).deep_scanned = True
        host.deep_scanned = True


def service_url(ip: str, port: int) -> str:
    scheme = "https" if port in {443, 8443, 9443, 5480} else "http"
    return f"{scheme}://{ip}/" if port in {80, 443} else f"{scheme}://{ip}:{port}/"


def run_nuclei(top_hosts: list[Host], outdir: Path, dry_run: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if dry_run or not command_exists("nuclei"):
        return findings
    urls = []
    for host in top_hosts:
        for port in sorted(set(host.services) & WEB_PORTS):
            urls.append(service_url(host.ip, port))
    if not urls:
        return findings
    targets = outdir / "nuclei_targets.txt"
    output = outdir / "nuclei_safe.jsonl"
    targets.write_text("\n".join(urls) + "\n", encoding="utf-8")
    cmd = [
        "nuclei", "-l", str(targets), "-tags", SAFE_NUCLEI_TAGS, "-severity", SAFE_NUCLEI_SEVERITIES,
        "-exclude-tags", "bruteforce,fuzz,dos,intrusive,exploit", "-rl", "50", "-c", "25",
        "-timeout", "5", "-retries", "1",
        "-jsonl", "-o", str(output), "-silent",
    ]
    (outdir / "nuclei_command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
    info("Nuclei: running safe allowlisted local web checks")
    try:
        run(cmd, timeout=300)
    except subprocess.TimeoutExpired:
        warn("Nuclei timed out after 300 seconds; continuing with partial findings.")
    if output.exists():
        for line in output.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return findings


def find_browser() -> str:
    for name in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge"]:
        if command_exists(name):
            return name
    return ""


def capture_screenshots(top_hosts: list[Host], outdir: Path, dry_run: bool) -> int:
    if dry_run:
        return 0
    browser = find_browser()
    if not browser:
        return 0
    screenshot_dir = outdir / "screenshots"
    screenshot_dir.mkdir(exist_ok=True)
    captured = 0
    for host in top_hosts:
        for port in sorted(set(host.services) & WEB_PORTS):
            url = service_url(host.ip, port)
            path = screenshot_dir / f"{sanitize(host.ip)}_{port}.png"
            cmd = [
                browser, "--headless", "--disable-gpu", "--no-sandbox", "--ignore-certificate-errors",
                "--window-size=1440,1000", f"--screenshot={path}", url,
            ]
            try:
                run(cmd, timeout=20)
            except Exception:
                continue
            if path.exists() and path.stat().st_size > 0:
                host.screenshots.append({"url": url, "path": str(path.relative_to(outdir))})
                captured += 1
    return captured


def sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def severity_for(host: Host, service: Service) -> str:
    if service.port in {23, 3389, 5985, 5986, 6379, 9200, 27017}:
        return "High"
    if service.port in HIGH_IMPACT_PORTS:
        return "Medium"
    return "Low"


def build_findings(top_hosts: list[Host], nuclei_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for host in top_hosts:
        ports = set(host.services)
        if {88, 389, 445} & ports and len({53, 88, 389, 445} & ports) >= 3:
            findings.append(finding(
                "Potential domain controller or identity infrastructure identified", "High", host,
                "Kerberos/LDAP/SMB/DNS role indicators", ", ".join(map(str, sorted({53, 88, 389, 445} & ports))),
                "Treat as high-value infrastructure. Confirm role and ensure only required systems can reach identity services.",
                ["nmap -Pn -sV -sC -p 53,88,389,445 " + host.ip, "ldapsearch -x -H ldap://" + host.ip + " -s base"],
            ))
        for service in sorted(host.services.values(), key=lambda s: s.port):
            if service.port in HIGH_IMPACT_PORTS:
                title = {
                    23: "Telnet exposed internally",
                    445: "SMB exposed on prioritized host",
                    3389: "RDP exposed internally",
                    161: "SNMP service exposed",
                }.get(service.port, f"{service.name.upper() if service.name else 'Service'} exposed on port {service.port}")
                findings.append(finding(
                    title, severity_for(host, service), host, f"{service.protocol}/{service.port}",
                    service.label,
                    "This is an exposure finding, not a vulnerability claim. Validate business need and restrict access where possible.",
                    verification_commands(host, service),
                ))
        if len(ports) >= 8:
            findings.append(finding(
                "Multiple management or service ports exposed on same host", "Medium", host,
                "Host service surface", f"{len(ports)} open TCP ports: {', '.join(map(str, sorted(ports)))}",
                "Hosts with broad service exposure deserve manual review, patch validation, and network segmentation checks.",
                ["nmap -Pn -sV -sC -p " + ",".join(map(str, sorted(ports))) + " " + host.ip],
            ))
    for item in nuclei_findings:
        host = str(item.get("host") or item.get("matched-at") or "")
        info_block = item.get("info", {})
        findings.append({
            "title": "Nuclei reported safe misconfiguration finding: " + str(info_block.get("name", "Unnamed finding")),
            "severity": str(info_block.get("severity", "Info")).title(),
            "host": host,
            "service": item.get("matched-at", host),
            "evidence": item.get("template-id", ""),
            "interpretation": "Nuclei matched a safe local-network template. Review the raw Nuclei JSONL artifact before treating this as confirmed risk.",
            "risk": str(info_block.get("description", "Potential exposure or misconfiguration detected.")),
            "remediation": "Validate the service configuration and apply vendor hardening guidance.",
            "commands": ["nuclei -u " + host + " -tags " + SAFE_NUCLEI_TAGS + " -severity " + SAFE_NUCLEI_SEVERITIES],
            "confidence": "Medium",
            "limitations": "Template-based evidence; no exploit or state-changing validation was performed.",
        })
    return findings


def finding(title: str, severity: str, host: Host, service: str, evidence: str, remediation: str, commands: list[str]) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "host": host.ip,
        "service": service,
        "evidence": evidence,
        "interpretation": "Detected during safe discovery and service enumeration.",
        "risk": "May increase internal attack surface or expose a high-value administrative service to local network users.",
        "remediation": remediation,
        "commands": commands,
        "confidence": "Medium",
        "limitations": "No credentialed checks, brute force, exploit execution, or destructive validation were performed.",
    }


def verification_commands(host: Host, service: Service) -> list[str]:
    ip = host.ip
    if service.port in WEB_PORTS:
        url = service_url(ip, service.port)
        return [f"curl -k -I --max-time 10 {url}", f"curl -k --max-time 10 {url}", f"nmap -Pn -sV -sC -p {service.port} {ip}"]
    if service.port == 445:
        return [f"nmap -Pn -sV -sC -p 445 {ip}", f"smbclient -L //{ip}/ -N", f"rpcclient -U \"\" -N {ip}"]
    if service.port == 53:
        return [f"nmap -Pn -sV -sC -p 53 {ip}", f"dig @{ip} version.bind chaos txt"]
    if service.port in {389, 636}:
        scheme = "ldaps" if service.port == 636 else "ldap"
        return [f"nmap -Pn -sV -sC -p {service.port} {ip}", f"ldapsearch -x -H {scheme}://{ip} -s base"]
    return [f"nmap -Pn -sV -sC -p {service.port} {ip}"]


def image_data(path: Path) -> str:
    if not path.exists():
        return ""
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def render_report(ctx: dict[str, Any], hosts: dict[str, Host], top_hosts: list[Host], findings: list[dict[str, Any]], outdir: Path, commands: dict[str, str], dry_run: bool) -> Path:
    report = outdir / "report.html"
    total_services = sum(len(h.services) for h in hosts.values())
    network_text = ", ".join(map(str, ctx["networks"]))
    host_rows = []
    for h in sorted(hosts.values(), key=lambda x: (-x.score, ip_sort_key(x.ip))):
        host_rows.append(f"<tr><td>{esc(h.ip)}</td><td>{esc(h.hostname)}</td><td>{esc(h.mac)}</td><td>{esc(h.vendor)}</td><td>{len(h.services)}</td><td>{h.score}</td><td>{esc(', '.join(sorted(h.sources)))}</td></tr>")
    top_cards = []
    for idx, h in enumerate(top_hosts, 1):
        services = ", ".join(f"{s.port}/{s.name or 'unknown'}" for s in sorted(h.services.values(), key=lambda x: x.port)) or "No open TCP services found in quick scan"
        screenshots = ""
        for shot in h.screenshots:
            data = image_data(outdir / shot["path"])
            if data:
                screenshots += f'<figure><img src="{data}" alt="Screenshot {esc(shot["url"])}"><figcaption>{esc(shot["url"])}</figcaption></figure>'
        top_cards.append(f"""
        <details class="host-card" open>
          <summary><span>#{idx} {esc(h.ip)} {esc(h.hostname)}</span><strong>{h.score}</strong></summary>
          <p><b>Services:</b> {esc(services)}</p>
          <p><b>Ranking rationale:</b> {esc('; '.join(h.ranking_reasons))}</p>
          <p><b>MAC/Vendor:</b> {esc(h.mac)} {esc(h.vendor)}</p>
          <p><b>Evidence sources:</b> {esc(', '.join(sorted(h.sources)))}</p>
          {screenshots}
        </details>""")
    finding_cards = []
    for f in findings:
        sev = esc(f["severity"]).lower()
        cmds = "".join(f"<code>{esc(c)}</code>" for c in f.get("commands", []))
        finding_cards.append(f"""
        <article class="finding {sev}">
          <h3>{esc(f['title'])}</h3>
          <div class="meta"><span>{esc(f['severity'])}</span><span>{esc(f['host'])}</span><span>{esc(f['service'])}</span><span>Confidence: {esc(f['confidence'])}</span></div>
          <p><b>Evidence:</b> {esc(f['evidence'])}</p>
          <p><b>Interpretation:</b> {esc(f['interpretation'])}</p>
          <p><b>Risk/impact:</b> {esc(f['risk'])}</p>
          <p><b>Recommended remediation:</b> {esc(f['remediation'])}</p>
          <p><b>Assumptions/limitations:</b> {esc(f['limitations'])}</p>
          <div class="commands">{cmds}</div>
        </article>""")
    command_rows = "".join(f"<tr><td>{esc(k)}</td><td><code>{esc(v)}</code></td></tr>" for k, v in commands.items() if v)
    skipped = "".join(f"<li>{esc(x)}</li>" for x in ctx.get("skipped_routes", [])) or "<li>No unsafe broad routes were scanned.</li>"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.write_text(f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Local Attack Surface Report - {esc(ctx['interface'])}</title>
  <style>
    :root {{ --bg:#f6f7f9; --panel:#fff; --text:#17202a; --muted:#5d6d7e; --line:#d7dde5; --high:#b42318; --med:#b54708; --low:#175cd3; --ok:#067647; }}
    body {{ margin:0; font:14px/1.5 Arial, sans-serif; color:var(--text); background:var(--bg); }}
    header {{ background:#111827; color:#fff; padding:28px 36px; }}
    header h1 {{ margin:0 0 6px; font-size:28px; }}
    main {{ max-width:1320px; margin:0 auto; padding:24px; }}
    section, .host-card, .finding {{ background:var(--panel); border:1px solid var(--line); border-radius:8px; margin:0 0 16px; padding:18px; box-shadow:0 1px 2px rgba(16,24,40,.04); }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; margin:16px 0; }}
    .card {{ background:#fff; border:1px solid var(--line); border-radius:8px; padding:16px; }}
    .card strong {{ display:block; font-size:26px; }}
    h2 {{ margin:0 0 12px; font-size:20px; }}
    table {{ width:100%; border-collapse:collapse; }}
    th, td {{ border-bottom:1px solid var(--line); padding:9px; text-align:left; vertical-align:top; }}
    th {{ background:#eef2f6; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }}
    code {{ display:block; margin:6px 0; padding:8px; background:#111827; color:#e5e7eb; border-radius:6px; overflow:auto; }}
    .muted {{ color:var(--muted); }}
    .meta {{ display:flex; flex-wrap:wrap; gap:8px; margin:8px 0; }}
    .meta span {{ background:#eef2f6; padding:4px 8px; border-radius:999px; }}
    .finding.high {{ border-left:5px solid var(--high); }}
    .finding.medium {{ border-left:5px solid var(--med); }}
    .finding.low, .finding.info {{ border-left:5px solid var(--low); }}
    summary {{ cursor:pointer; display:flex; justify-content:space-between; gap:12px; font-size:16px; }}
    figure {{ margin:12px 0; }}
    img {{ max-width:100%; border:1px solid var(--line); border-radius:6px; }}
    ul {{ margin-top:8px; }}
  </style>
</head>
<body>
<header>
  <h1>Local Attack Surface Report</h1>
  <div>Authorized internal assessment via interface <b>{esc(ctx['interface'])}</b> - generated {esc(generated)}</div>
</header>
<main>
  <section>
    <h2>Executive Summary</h2>
    <p>This report maps local/internal hosts reachable through the selected interface, ranks likely high-value systems, and performs deeper safe enumeration only on the top 10 hosts. It does not perform brute force, credential attacks, exploit execution, denial-of-service checks, or state-changing tests.</p>
    <div class="cards">
      <div class="card"><span>Live hosts</span><strong>{len(hosts)}</strong></div>
      <div class="card"><span>Open services</span><strong>{total_services}</strong></div>
      <div class="card"><span>Deep scanned</span><strong>{len([h for h in top_hosts if h.deep_scanned])}</strong></div>
      <div class="card"><span>Findings</span><strong>{len(findings)}</strong></div>
    </div>
  </section>
  <section>
    <h2>Scan Metadata and Scope</h2>
    <table>
      <tr><th>Interface</th><td>{esc(ctx['interface'])}</td></tr>
      <tr><th>Addresses</th><td>{esc(', '.join(ctx['addresses']))}</td></tr>
      <tr><th>Detected local scope</th><td>{esc(network_text)}</td></tr>
      <tr><th>Gateway candidates</th><td>{esc(', '.join(ctx['gateways']) or 'None detected')}</td></tr>
      <tr><th>Dry run</th><td>{esc(dry_run)}</td></tr>
    </table>
    <h3>Safety Controls</h3>
    <ul>
      <li>Only private, link-local, ULA, or directly connected internal ranges from the selected interface are considered.</li>
      <li>Default routes, public IP ranges, loopback, multicast, broadcast, documentation ranges, and overly broad IPv4 routes are not scanned.</li>
      <li>Deep scans, screenshots, and Nuclei checks are limited to the prioritized top 10 hosts.</li>
      <li>Nuclei is restricted to safe local web tags and excludes brute force, fuzzing, DoS, intrusive, and exploit tags.</li>
    </ul>
    <h3>Skipped Broad or Unsafe Routes</h3>
    <ul>{skipped}</ul>
  </section>
  <section>
    <h2>Top 10 Prioritized Hosts</h2>
    {''.join(top_cards) or '<p class="muted">No prioritized hosts available.</p>'}
  </section>
  <section>
    <h2>Findings and Exposures</h2>
    {''.join(finding_cards) or '<p class="muted">No service exposure findings were generated. This does not prove the network is secure.</p>'}
  </section>
  <section>
    <h2>Discovered Host Inventory</h2>
    <table><thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th><th>Services</th><th>Score</th><th>Sources</th></tr></thead><tbody>{''.join(host_rows)}</tbody></table>
  </section>
  <section>
    <h2>Reproducibility</h2>
    <p>Raw scan artifacts are stored beside this report. Commands below are recorded for auditability.</p>
    <table><thead><tr><th>Phase</th><th>Command</th></tr></thead><tbody>{command_rows}</tbody></table>
  </section>
  <section>
    <h2>What To Do Next</h2>
    <ul>
      <li>Verify high-value host roles with administrators before assigning ownership or remediation priority.</li>
      <li>Confirm whether exposed administrative services are required from the assessed network segment.</li>
      <li>Apply segmentation, host firewalls, patching, and vendor hardening based on business need.</li>
      <li>Run credentialed configuration reviews separately where authorized.</li>
    </ul>
    <h2>Limitations</h2>
    <p>Results depend on local privileges, installed tools, host firewalls, ICMP/ARP behavior, and scan timing. Absence of evidence is not evidence of absence.</p>
  </section>
</main>
</body>
</html>
""", encoding="utf-8")
    return report


def collect_commands(outdir: Path) -> dict[str, str]:
    commands = {}
    for path in sorted(outdir.glob("*_command.txt")):
        commands[path.stem.replace("_command", "")] = path.read_text(encoding="utf-8", errors="replace").strip()
    return commands


def main() -> int:
    args = parse_args()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    outdir = REPORT_ROOT / timestamp
    outdir.mkdir(parents=True, exist_ok=True)

    deps = {
        "required": ["python3", "ip"],
        "optional": ["nmap", "arp", "arp-scan", "nuclei", "chromium/google-chrome", "resolvectl"],
    }
    (outdir / "dependencies.json").write_text(json.dumps({
        "required": {d: command_exists(d) for d in deps["required"]},
        "optional": {
            "nmap": command_exists("nmap"),
            "arp": command_exists("arp"),
            "arp-scan": command_exists("arp-scan"),
            "nuclei": command_exists("nuclei"),
            "browser": bool(find_browser()),
            "resolvectl": command_exists("resolvectl"),
        },
        "root": os.geteuid() == 0,
    }, indent=2), encoding="utf-8")

    ctx = get_interface_context(args.interface)
    info("Detected local scope: " + ", ".join(map(str, ctx["networks"])))
    if ctx["skipped_routes"]:
        warn("Skipped unsafe broad route(s); see report for details.")
    if os.geteuid() != 0:
        warn("Running without root privileges; ARP discovery and some service fingerprints may be less complete.")

    info("Discovery: collecting passive neighbors and safe active signals")
    hosts = discover_hosts(ctx, outdir, args.dry_run)
    info(f"Discovery: {len(hosts)} live/candidate hosts found")

    quick_scan(hosts, outdir, args.dry_run)
    info(f"Quick scan: {len(hosts)} hosts processed")

    top_hosts = classify_and_rank(hosts, ctx["gateways"])
    info(f"Prioritization: selected top {len(top_hosts)} high-value hosts")

    deep_scan(top_hosts, hosts, outdir, args.dry_run)
    top_hosts = classify_and_rank(hosts, ctx["gateways"])

    nuclei_findings = run_nuclei(top_hosts, outdir, args.dry_run)
    screenshots = capture_screenshots(top_hosts, outdir, args.dry_run)
    info(f"Screenshots: captured {screenshots} web services")

    findings = build_findings(top_hosts, nuclei_findings)
    artifact = {
        "context": {
            **ctx,
            "networks": [str(n) for n in ctx["networks"]],
        },
        "hosts": [
            {
                "ip": h.ip, "hostname": h.hostname, "mac": h.mac, "vendor": h.vendor,
                "sources": sorted(h.sources), "score": h.score, "ranking_reasons": h.ranking_reasons,
                "services": [vars(s) for s in h.services.values()],
            }
            for h in hosts.values()
        ],
        "findings": findings,
    }
    (outdir / "scan_data.json").write_text(json.dumps(artifact, indent=2, default=str), encoding="utf-8")
    report = render_report(ctx, hosts, top_hosts, findings, outdir, collect_commands(outdir), args.dry_run)
    info(f"HTML report: {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
