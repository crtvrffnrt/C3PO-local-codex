import ipaddress
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import local_scanner as scanner


FIXTURES = Path(__file__).parent / "fixtures"


class LocalScannerTests(unittest.TestCase):
    def test_private_public_filtering(self):
        self.assertTrue(scanner.ipv4_scope_allowed(ipaddress.ip_network("192.168.178.0/24")))
        self.assertTrue(scanner.ipv4_scope_allowed(ipaddress.ip_network("10.0.0.0/24")))
        self.assertFalse(scanner.ipv4_scope_allowed(ipaddress.ip_network("8.8.8.0/24")))
        self.assertFalse(scanner.ipv4_scope_allowed(ipaddress.ip_network("127.0.0.0/8")))
        self.assertFalse(scanner.ipv4_scope_allowed(ipaddress.ip_network("169.254.0.0/16")))

    def test_legacy_route_netmask_conversion(self):
        entry = scanner.parse_ipv4_route_line((FIXTURES / "tun0_route_legacy.txt").read_text().splitlines()[0], source="legacy")
        self.assertIsNotNone(entry)
        self.assertEqual(str(entry.network), "10.1.0.0/16")
        self.assertEqual(entry.via, "10.81.0.129")
        self.assertEqual(entry.dev, "tun0")

    def test_modern_route_parsing(self):
        entry = scanner.parse_ipv4_route_line("10.81.0.0/24 dev tun0 proto kernel scope link src 10.81.0.2", source="main")
        self.assertIsNotNone(entry)
        self.assertEqual(str(entry.network), "10.81.0.0/24")
        self.assertEqual(entry.dev, "tun0")
        self.assertEqual(entry.src, "10.81.0.2")

    def test_default_and_public_routes_are_excluded(self):
        entry = scanner.parse_ipv4_route_line("default via fritz.box dev eth1 proto dhcp metric 20")
        self.assertIsNotNone(entry)
        self.assertFalse(scanner.ipv4_scope_allowed(entry.network))
        self.assertFalse(scanner.ipv4_scope_allowed(ipaddress.ip_network("8.8.8.0/24")))

    def test_parse_neighbors(self):
        hosts = scanner.parse_neighbors("192.168.178.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n192.168.178.99 dev wlan0 FAILED\n")
        self.assertIn("192.168.178.1", hosts)
        self.assertNotIn("192.168.178.99", hosts)
        self.assertEqual(hosts["192.168.178.1"].mac, "aa:bb:cc:dd:ee:ff")

    def test_nmap_xml_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nmap.xml"
            path.write_text(
                """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="192.168.178.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="FRITZ!Box"/></port></ports></host></nmaprun>""",
                encoding="utf-8",
            )
            hosts = scanner.parse_nmap_xml(path)
            self.assertIn("192.168.178.1", hosts)
            self.assertIn(80, hosts["192.168.178.1"].services)

    def test_tcp_discovery_finds_ping_blocked_hosts(self):
        ping_xml = """<?xml version="1.0"?><nmaprun></nmaprun>"""
        tcp_xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.10.10.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="88"><state state="open"/><service name="kerberos"/></port></ports>
  </host>
  <host>
    <status state="up"/>
    <address addr="10.10.10.11" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port></ports>
  </host>
</nmaprun>"""

        def fake_run_command(cmd, outdir, name, timeout, check=False):
            stdout_path = outdir / "logs" / f"{name}.stdout.txt"
            stderr_path = outdir / "logs" / f"{name}.stderr.txt"
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            xml_path = None
            for arg in cmd:
                if str(arg).endswith(".xml"):
                    xml_path = Path(arg)
                    break
            if xml_path is not None:
                xml_path.write_text(tcp_xml if name.startswith("nmap_tcp_discovery") else ping_xml, encoding="utf-8")
            return {
                "name": name,
                "argv": cmd,
                "redacted_argv": cmd,
                "start": "now",
                "timeout_seconds": timeout,
                "stdout_path": str(stdout_path.relative_to(outdir)),
                "stderr_path": str(stderr_path.relative_to(outdir)),
                "exit_code": 0,
                "timed_out": False,
                "error": "",
                "end": "now",
                "duration_seconds": 0.01,
            }

        with tempfile.TemporaryDirectory() as tmp, patch.object(scanner, "command_exists", side_effect=lambda name: name == "nmap"), patch.object(scanner, "run_command", side_effect=fake_run_command), patch.object(scanner, "reverse_dns", return_value=""):
            hosts = scanner.discover_hosts({"networks": [ipaddress.ip_network("10.10.10.0/24")], "gateways": [], "neigh": "", "interface": "tun0"}, Path(tmp), False, {"scan_batches": [], "screenshots": []})
            self.assertIn("10.10.10.10", hosts)
            self.assertIn("10.10.10.11", hosts)
            self.assertIn(88, hosts["10.10.10.10"].services)
            self.assertIn(445, hosts["10.10.10.11"].services)

    def test_route_validation_uses_effective_tun0_route(self):
        addr_data = [{"addr_info": [{"family": "inet", "local": "10.81.0.2", "prefixlen": 24}]}]
        route_dev = scanner.parse_ipv4_route_table((FIXTURES / "tun0_route_main.txt").read_text(), source="dev:tun0")
        route_main = scanner.parse_ipv4_route_table((FIXTURES / "tun0_route_main.txt").read_text(), source="main")
        outputs = {
            "10.1.0.1": "10.1.0.1 via 10.81.0.129 dev tun0 src 10.81.0.2",
            "10.81.0.1": "10.81.0.1 dev tun0 src 10.81.0.2",
            "10.10.10.1": "10.10.10.1 via 10.81.0.129 dev tun0 src 10.81.0.2",
            "192.168.178.1": "192.168.178.1 via 10.81.0.129 dev tun0 src 10.81.0.2",
        }

        def fake_run_command(cmd, outdir, name, timeout, check=False):
            rep = cmd[-1]
            stdout_path = outdir / "logs" / f"{name}.stdout.txt"
            stderr_path = outdir / "logs" / f"{name}.stderr.txt"
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text(outputs.get(rep, ""), encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return {
                "name": name,
                "argv": cmd,
                "redacted_argv": cmd,
                "start": "now",
                "timeout_seconds": timeout,
                "stdout_path": str(stdout_path.relative_to(outdir)),
                "stderr_path": str(stderr_path.relative_to(outdir)),
                "exit_code": 0,
                "timed_out": False,
                "error": "",
                "end": "now",
                "duration_seconds": 0.01,
            }

        with tempfile.TemporaryDirectory() as tmp, patch.object(scanner, "run_command", side_effect=fake_run_command):
            scope = scanner.validate_route_scope("tun0", addr_data, route_dev, route_main, Path(tmp))
            self.assertIn(ipaddress.ip_network("10.1.0.0/16"), scope.validated_networks)
            self.assertIn(ipaddress.ip_network("10.81.0.0/24"), scope.validated_networks)
            self.assertIn(ipaddress.ip_network("10.10.10.0/24"), scope.validated_networks)
            self.assertIn(ipaddress.ip_network("192.168.178.0/24"), scope.validated_networks)
            self.assertTrue(any(item["network"] == "192.168.178.0/24" for item in scope.overlap_warnings))

    def test_fritzbox_prioritization(self):
        host = scanner.Host(ip="192.168.178.1")
        host.sources.add("gateway")
        top = scanner.classify_and_rank({"192.168.178.1": host}, ["192.168.178.1"])
        self.assertEqual(top[0].ip, "192.168.178.1")
        self.assertTrue(any("FritzBox" in reason for reason in top[0].ranking_reasons))

    def test_dns_srv_dc_discovery(self):
        hosts = {
            "10.10.10.10": scanner.Host(ip="10.10.10.10"),
            "10.10.10.11": scanner.Host(ip="10.10.10.11"),
        }

        def fake_command_exists(name):
            return name == "dig"

        def fake_run_optional_command(cmd, outdir, name, timeout=20):
            text = ""
            if "ldap" in " ".join(cmd):
                text = (FIXTURES / "dns_srv_ldap.txt").read_text()
            elif "kerberos" in " ".join(cmd):
                text = (FIXTURES / "dns_srv_kerberos.txt").read_text()
            elif cmd[-2:] == ["dc01.example.internal", "A"] or cmd[-1] == "dc01.example.internal":
                text = "10.10.10.10\n"
            elif cmd[-2:] == ["dc02.example.internal", "A"] or cmd[-1] == "dc02.example.internal":
                text = "10.10.10.11\n"
            stdout_path = Path(outdir) / "logs" / f"{name}.stdout.txt"
            stderr_path = Path(outdir) / "logs" / f"{name}.stderr.txt"
            stdout_path.parent.mkdir(parents=True, exist_ok=True)
            stdout_path.write_text(text, encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return text, {
                "name": name,
                "argv": cmd,
                "redacted_argv": cmd,
                "start": "now",
                "timeout_seconds": timeout,
                "stdout_path": str(stdout_path.relative_to(outdir)),
                "stderr_path": str(stderr_path.relative_to(outdir)),
                "exit_code": 0,
                "timed_out": False,
                "error": "",
                "end": "now",
                "duration_seconds": 0.01,
            }

        with tempfile.TemporaryDirectory() as tmp, patch.object(scanner, "command_exists", side_effect=fake_command_exists), patch.object(scanner, "run_optional_command", side_effect=fake_run_optional_command):
            candidates = scanner.discover_domain_controllers({"networks": [ipaddress.ip_network("10.10.10.0/24")], "gateways": []}, hosts, Path(tmp), {"scan_batches": []}, False)
            self.assertIn("10.10.10.10", candidates)
            self.assertIn("10.10.10.11", candidates)
            self.assertTrue(all(item["confirmed"] for item in candidates.values()))

    def test_nxc_protocol_mapping(self):
        host = scanner.Host(ip="192.168.178.10")
        for port in [445, 389, 5985, 22, 3389, 5901, 2049]:
            host.services[port] = scanner.Service(port=port)
        protocols = scanner.protocols_for_hosts([host])
        self.assertTrue({"smb", "ldap", "winrm", "ssh", "rdp", "vnc", "nfs"}.issubset(protocols))

    def test_nmap_dc_inference(self):
        hosts = scanner.parse_nmap_xml(FIXTURES / "nmap_dc.xml")
        with tempfile.TemporaryDirectory() as tmp, patch.object(scanner, "command_exists", return_value=False):
            candidates = scanner.discover_domain_controllers({"networks": [ipaddress.ip_network("10.10.10.0/24")], "gateways": []}, hosts, Path(tmp), {"scan_batches": []}, False)
            self.assertIn("10.10.10.10", candidates)
            self.assertEqual(candidates["10.10.10.10"]["confidence"], "high")
            self.assertIn("Identity services exposed", " ".join(candidates["10.10.10.10"]["evidence"]))

    def test_nxc_dc_inference(self):
        hosts = {
            "10.10.10.10": scanner.Host(ip="10.10.10.10"),
        }
        hosts["10.10.10.10"].services[389] = scanner.Service(port=389, name="ldap", product="Microsoft Windows Active Directory LDAP")
        hosts["10.10.10.10"].services[445] = scanner.Service(port=445, name="microsoft-ds", product="Windows Server")
        with tempfile.TemporaryDirectory() as tmp, patch.object(scanner, "command_exists", return_value=False):
            nxc_out = Path(tmp) / "nxc"
            (nxc_out / "jsonl").mkdir(parents=True, exist_ok=True)
            (nxc_out / "reports").mkdir(parents=True, exist_ok=True)
            (nxc_out / "json").mkdir(parents=True, exist_ok=True)
            (nxc_out / "jsonl" / "events.jsonl").write_text((FIXTURES / "nxc_dc_events.jsonl").read_text(), encoding="utf-8")
            (nxc_out / "jsonl" / "findings.jsonl").write_text("", encoding="utf-8")
            (nxc_out / "reports" / "markdown-summary.md").write_text("# NXC Summary\n\nProtocols: smb, ldap\n", encoding="utf-8")
            (nxc_out / "json" / "summary.json").write_text(json.dumps({"selected_protocols": ["smb", "ldap"]}), encoding="utf-8")
            candidates = scanner.discover_domain_controllers({"networks": [ipaddress.ip_network("10.10.10.0/24")], "gateways": []}, hosts, Path(tmp), {"scan_batches": []}, False, nxc_outdir=nxc_out)
            self.assertIn("10.10.10.10", candidates)
            self.assertTrue(any("NXC output references example.internal" in item for item in candidates["10.10.10.10"]["evidence"]))

    def test_top_hosts_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            host = scanner.Host(ip="192.168.178.1")
            scanner.classify_and_rank({"192.168.178.1": host}, ["192.168.178.1"])
            ctx = {"networks": [ipaddress.ip_network("192.168.178.0/24")]}
            scanner.write_top_hosts([host], out, ctx, {})
            data = json.loads((out / "top-hosts.json").read_text())
            self.assertEqual(data["fritzbox_status"], "reachable_and_prioritized")
            self.assertIsInstance(data["hosts"], list)

    def test_top_ten_includes_two_dcs(self):
        hosts = {
            "10.10.10.10": scanner.Host(ip="10.10.10.10"),
            "10.10.10.11": scanner.Host(ip="10.10.10.11"),
            "192.168.178.1": scanner.Host(ip="192.168.178.1"),
        }
        for ip, ports in {
            "10.10.10.10": [53, 88, 389, 445, 5985],
            "10.10.10.11": [53, 88, 389, 445, 5985],
            "192.168.178.1": [21, 53, 443],
        }.items():
            for port in ports:
                hosts[ip].services[port] = scanner.Service(port=port, name="svc")
        dc_candidates = {
            "10.10.10.10": {"ip": "10.10.10.10", "confidence": "high", "evidence": ["DNS SRV", "LDAP", "Kerberos"], "open_ports": [53, 88, 389, 445, 5985], "reason": "dc", "confirmed": True, "hostname": "dc01.example.internal", "source_artifacts": [], "sources": [], "nmap_evidence": [], "nxc_evidence": [], "dns_evidence": []},
            "10.10.10.11": {"ip": "10.10.10.11", "confidence": "high", "evidence": ["DNS SRV", "LDAP", "Kerberos"], "open_ports": [53, 88, 389, 445, 5985], "reason": "dc", "confirmed": True, "hostname": "dc02.example.internal", "source_artifacts": [], "sources": [], "nmap_evidence": [], "nxc_evidence": [], "dns_evidence": []},
        }
        ranked = scanner.classify_and_rank(hosts, ["192.168.178.1"], dc_candidates)
        top = scanner.ensure_required_top_hosts(ranked, hosts, dc_candidates)
        self.assertIn("10.10.10.10", [host.ip for host in top])
        self.assertIn("10.10.10.11", [host.ip for host in top])

    def test_performance_aggregation_records_timeouts_and_partial_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "performance").mkdir(parents=True, exist_ok=True)
            (out / "commands.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"name": "nmap_fast_10.1.0.0_16", "duration_seconds": 12.5, "timeout_seconds": 120, "timed_out": False, "exit_code": 0, "redacted_argv": ["nmap"]}),
                        json.dumps({"name": "nuclei_safe", "duration_seconds": 160.1, "timeout_seconds": 180, "timed_out": True, "exit_code": 124, "redacted_argv": ["nuclei"]}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            summary = scanner.aggregate_performance(out, {"scan_batches": [{"phase": "fast-scan", "network": "10.1.0.0/16", "host_count": 12, "duration_seconds": 12.5, "timeout_seconds": 120, "timed_out": False, "exit_code": 0, "command": ["nmap"]}], "screenshots": []})
            self.assertIn("fast_scan", summary["phase_durations"])
            self.assertGreaterEqual(len(summary["timeouts"]), 1)
            self.assertTrue((out / "performance" / "phase_durations.json").exists())
            self.assertTrue((out / "performance" / "timeouts.json").exists())

    def test_nuclei_placeholder_artifacts_when_no_web_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            host = scanner.Host(ip="10.10.10.10")
            findings = scanner.run_nuclei([host], out, False)
            self.assertEqual(findings, [])
            self.assertTrue((out / "nuclei_safe.jsonl").exists())
            self.assertIn("No HTTP/HTTPS targets selected", (out / "nuclei_targets.txt").read_text())

    def test_report_renders_route_warnings_and_dc_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            host = scanner.Host(ip="10.10.10.10", hostname="dc01.example.internal", role_guess="domain controller candidate", role_confidence="high")
            host.services[53] = scanner.Service(port=53, name="domain", product="Microsoft DNS")
            host.services[389] = scanner.Service(port=389, name="ldap", product="Microsoft AD")
            host.dc_candidate = True
            host.dc_confidence = "high"
            host.dc_evidence = ["DNS SRV", "LDAP", "Kerberos"]
            host.screenshot_path = "screenshots/dc01.png"
            hosts = {host.ip: host}
            top_hosts = [host]
            findings = [{"severity": "High", "status": "inferred", "host": host.ip, "title": "Internal exposure on 389/ldap", "evidence": "tcp/389 ldap", "recommendation": "Restrict access", "cves": []}]
            dc_candidates = {host.ip: {"ip": host.ip, "hostname": host.hostname, "confidence": "high", "confirmed": True, "reason": "DNS SRV records identify a likely domain controller", "open_ports": [53, 389], "evidence": ["DNS SRV"], "source_artifacts": ["domain/example.internal_srv_ldap.txt"], "sources": ["dns-srv"], "nmap_evidence": [], "nxc_evidence": [], "dns_evidence": ["_ldap._tcp.dc._msdcs.example.internal"]}}
            (out / "top-hosts.json").write_text(json.dumps({"fritzbox_status": "not_in_scope", "hosts": [scanner.host_to_dict(host)]}), encoding="utf-8")
            report = scanner.render_report(
                out,
                {
                    "interface": "tun0",
                    "addresses": ["10.81.0.2/24"],
                    "candidate_networks": ["10.81.0.0/24"],
                    "networks": [ipaddress.ip_network("10.81.0.0/24")],
                    "validated_networks": ["10.81.0.0/24"],
                    "gateways": [],
                    "route_overlap_warnings": [{"network": "192.168.178.0/24", "effective_dev": "tun0", "effective_via": "10.81.0.129", "competing_routes": [{"dev": "eth1"}]}],
                    "route_get_samples": [{"network": "10.81.0.0/24", "representative_ip": "10.81.0.1", "effective_dev": "tun0", "stdout": "10.81.0.1 dev tun0", "stderr": ""}],
                    "route_excluded_networks": ["default via eth1"],
                },
                hosts,
                top_hosts,
                findings,
                {"nmap": {"installed": True}, "nuclei": {"installed": True}},
                {"model": "gpt-5.5", "reasoning_profile": "medium"},
                {"selected_protocols": ["smb"], "ran": True},
                dc_candidates,
                {"phase_durations": {"fast_scan": {"duration_seconds": 1.2, "timeout_count": 0, "commands": ["nmap_fast_10.81.0.0_24"]}}, "timeouts": [], "slow_hosts": [], "scan_batches": [], "screenshots": [{"host": host.ip}]},
            )
            html_text = report.read_text(encoding="utf-8")
            self.assertIn("Management Summary", html_text)
            self.assertIn("Validated tun0 networks", html_text)
            self.assertIn("Domain Controller Candidates", html_text)
            self.assertIn("Verification commands", html_text)

    def test_nxc_safety_gate_requires_authorization(self):
        result = subprocess.run(
            [
                "python3",
                "tools/nxc_phase.py",
                "--targets",
                "/dev/null",
                "--service-map",
                "/dev/null",
                "--out",
                tempfile.mkdtemp(),
                "--run-id",
                "test",
                "--workspace",
                "test",
                "--protocols",
                "smb",
                "--mode",
                "recon",
                "--threads",
                "1",
                "--timeout",
                "1",
                "--jitter",
                "0",
                "--dns-timeout",
                "1",
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires --authorized", result.stderr + result.stdout)

    def test_no_active_shodan_or_docker_paths(self):
        allowed = {
            "README.md",
            "docs/architecture.md",
            "install.sh",
            "notes/refactor-plan.md",
        }
        offenders = []
        for root, dirs, files in os.walk("."):
            dirs[:] = [d for d in dirs if d not in {".git", "runs", "reports", "__pycache__", ".pytest_cache", "pytest_cache"}]
            for name in files:
                path = Path(root) / name
                rel = str(path).lstrip("./")
                if rel in allowed or rel.startswith("tests/"):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if re.search(r"shodan|docker compose|docker run|docker build|docker network|external attack surface", text, re.I):
                    offenders.append(rel)
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
