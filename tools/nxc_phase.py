#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PORT_PROTOCOLS = {
    "smb": {445, 139},
    "ldap": {389, 636, 3268, 3269},
    "winrm": {5985, 5986},
    "mssql": {1433},
    "ssh": {22},
    "ftp": {21},
    "rdp": {3389},
    "nfs": {111, 2049},
}
ALL_PROTOCOLS = ["smb", "ldap", "winrm", "wmi", "mssql", "ssh", "ftp", "rdp", "vnc", "nfs"]
DANGEROUS_WORDS = re.compile(r"(dump|secret|sam|lsa|ntds|lsass|dpapi|hash|kerberos|ticket|coerce|petitpotam|bloodhound|adcs|exec|shell|powershell|upload|download|password.change|spray)", re.I)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Safe NetExec/NXC phase wrapper")
    parser.add_argument("--targets", required=True)
    parser.add_argument("--service-map", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--protocols", default="")
    parser.add_argument("--mode", choices=["recon", "auth-check", "enum", "deep", "custom"], default="recon")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--jitter", default="0")
    parser.add_argument("--dns-server", default="")
    parser.add_argument("--dns-timeout", type=int, default=5)
    parser.add_argument("--dns-tcp", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--i-own-this-scope", "--authorized", action="store_true", dest="authorized")
    parser.add_argument("--redact-secrets", action="store_true")
    parser.add_argument("--audit-mode", action="store_true")
    parser.add_argument("--user", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--password-file", default="")
    parser.add_argument("--hash", default="")
    parser.add_argument("--hash-file", default="")
    parser.add_argument("--domain", default="")
    parser.add_argument("--local-auth", action="store_true")
    parser.add_argument("--kerberos", action="store_true")
    parser.add_argument("--use-kcache", action="store_true")
    parser.add_argument("--kdc-host", default="")
    parser.add_argument("--pfx-cert", default="")
    parser.add_argument("--pfx-pass", default="")
    parser.add_argument("--pfx-base64", default="")
    parser.add_argument("--pem-cert", default="")
    parser.add_argument("--pem-key", default="")
    parser.add_argument("--cred-id", default="")
    parser.add_argument("--allow-auth-spray", action="store_true")
    parser.add_argument("--allow-command-exec", action="store_true")
    parser.add_argument("--allow-secrets", action="store_true")
    parser.add_argument("--allow-file-download", action="store_true")
    parser.add_argument("--allow-coerce", action="store_true")
    parser.add_argument("--allow-bloodhound", action="store_true")
    parser.add_argument("--allow-adcs-abuse", action="store_true")
    parser.add_argument("--allow-password-change", action="store_true")
    parser.add_argument("--allow-modules", default="")
    parser.add_argument("--deny-modules", default="")
    parser.add_argument("--module-options", default="")
    parser.add_argument("--max-hosts", type=int, default=0)
    parser.add_argument("--rate-limit-per-host", type=int, default=1)
    return parser.parse_args()


def mkdirs(out: Path) -> None:
    for rel in ["meta/help", "meta/modules", "meta/module_options", "targets", "logs/raw", "logs/nxc", "logs/stderr", "jsonl", "json", "db_exports/raw", "db_exports/json", "native_artifacts/spider_plus", "native_artifacts/bloodhound", "native_artifacts/screenshots", "native_artifacts/other", "reports"]:
        (out / rel).mkdir(parents=True, exist_ok=True)
    for name in ["commands.jsonl", "events.jsonl", "findings.jsonl"]:
        (out / "jsonl" / name).touch(exist_ok=True)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, sort_keys=True) + "\n")


def read_targets(path: Path, max_hosts: int = 0) -> list[str]:
    values = []
    seen = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        value = line.strip()
        if not value or value.startswith("#") or value in seen:
            continue
        seen.add(value)
        values.append(value)
        if max_hosts and len(values) >= max_hosts:
            break
    return values


def service_protocol_targets(service_map: Path, targets: set[str], selected: list[str]) -> dict[str, list[str]]:
    data = json.loads(service_map.read_text(encoding="utf-8")) if service_map.exists() else []
    result = {p: set() for p in selected}
    for item in data:
        host = str(item.get("host", ""))
        if host not in targets:
            continue
        port = int(item.get("port", 0) or 0)
        name = str(item.get("name", "")).lower()
        for proto in selected:
            if proto == "wmi" and port in {135, 445}:
                result[proto].add(host)
            elif proto == "vnc" and 5900 <= port <= 5909:
                result[proto].add(host)
            elif port in PORT_PROTOCOLS.get(proto, set()):
                result[proto].add(host)
            elif proto == "mssql" and "ms-sql" in name:
                result[proto].add(host)
    return {k: sorted(v) for k, v in result.items() if v}


def run_capture(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or f"timeout after {timeout}s"


def redact(argv: list[str], enabled: bool) -> list[str]:
    if not enabled:
        return argv
    sensitive = {"--password", "-p", "--hash", "-H", "--pfx-pass", "--pfx-base64", "--pem-key", "--kdc-host"}
    out = []
    skip = False
    for item in argv:
        if skip:
            out.append("<redacted>")
            skip = False
            continue
        out.append(item)
        if item in sensitive:
            skip = True
    return out


def safety_check(args: argparse.Namespace, selected_modules: list[str]) -> None:
    if not args.authorized:
        raise SystemExit("[!] NXC phase requires --authorized or --i-own-this-scope.")
    multi_auth = sum(1 for x in [args.password, args.hash, args.password_file, args.hash_file] if x) > 1
    if multi_auth and not args.allow_auth_spray:
        raise SystemExit("[!] Multiple credential sources look like spraying; use --allow-auth-spray to override.")
    for module in selected_modules:
        if DANGEROUS_WORDS.search(module) and not any([args.allow_command_exec, args.allow_secrets, args.allow_file_download, args.allow_coerce, args.allow_bloodhound, args.allow_adcs_abuse, args.allow_password_change]):
            raise SystemExit(f"[!] Refusing potentially dangerous module without matching allow flag: {module}")
    if args.mode == "recon" and any([args.user, args.password, args.hash, args.password_file, args.hash_file, args.allow_modules]):
        raise SystemExit("[!] recon mode is no-auth and does not accept credentials or modules.")


def generic_args(args: argparse.Namespace) -> list[str]:
    values = ["-t", str(max(1, args.threads)), "--timeout", str(max(1, args.timeout)), "--jitter", str(args.jitter), "--no-progress"]
    if args.verbose:
        values.append("--verbose")
    if args.debug:
        values.append("--debug")
    if args.ipv6:
        values.append("-6")
    if args.dns_server:
        values += ["--dns-server", args.dns_server]
    if args.dns_tcp:
        values.append("--dns-tcp")
    values += ["--dns-timeout", str(max(1, args.dns_timeout))]
    return values


def auth_args(args: argparse.Namespace) -> list[str]:
    values = []
    if args.user:
        values += ["-u", args.user]
    if args.password:
        values += ["-p", args.password]
    if args.hash:
        values += ["-H", args.hash]
    if args.domain:
        values += ["-d", args.domain]
    if args.local_auth:
        values.append("--local-auth")
    if args.kerberos:
        values.append("-k")
    if args.use_kcache:
        values.append("--use-kcache")
    if args.kdc_host:
        values += ["--kdc-host", args.kdc_host]
    return values


def capture_capabilities(out: Path, protocols: list[str]) -> dict[str, Any]:
    caps: dict[str, Any] = {"protocols": {}}
    if not shutil.which("nxc"):
        return {"available": False, "protocols": {}}
    rc, stdout, stderr = run_capture(["nxc", "--version"], 20)
    (out / "meta/nxc_version.txt").write_text(stdout + stderr, encoding="utf-8")
    rc, stdout, stderr = run_capture(["nxc", "--help"], 20)
    (out / "meta/nxc_help.txt").write_text(stdout + stderr, encoding="utf-8")
    for proto in protocols:
        rc, stdout, stderr = run_capture(["nxc", proto, "--help"], 20)
        help_text = stdout + stderr
        (out / "meta/help" / f"{proto}.txt").write_text(help_text, encoding="utf-8")
        rc_l, stdout_l, stderr_l = run_capture(["nxc", proto, "-L"], 30)
        module_text = stdout_l + stderr_l
        (out / "meta/modules" / f"{proto}.txt").write_text(module_text, encoding="utf-8")
        modules = sorted(set(re.findall(r"^\s*([A-Za-z0-9_+-]+)\s{2,}", module_text, re.M)))
        caps["protocols"][proto] = {"help_exit": rc, "module_list_exit": rc_l, "modules": modules, "supports_log": "--log" in help_text}
    caps["available"] = True
    write_json(out / "meta/capabilities.json", caps)
    return caps


def parse_output(protocol: str, command_id: str, run_id: str, stdout_path: Path, out: Path) -> None:
    for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
        raw = line.strip()
        if not raw:
            continue
        host = ""
        port = None
        match = re.match(r"([A-Z0-9_-]+)\s+([0-9a-fA-F:.]+)\s+(\d+)\s+(.*)", raw)
        attrs: dict[str, Any] = {}
        if match:
            host = match.group(2)
            port = int(match.group(3))
            msg = match.group(4)
        else:
            msg = raw
        if "signing:" in raw.lower():
            attrs["smb_signing"] = raw
        if "smbv1:" in raw.lower():
            attrs["smbv1"] = raw
        if "[+]" in raw:
            finding_type = "auth_success" if "pwn3d" not in raw.lower() else "admin_rights"
            append_jsonl(out / "jsonl/findings.jsonl", {"finding_id": f"{command_id}-{abs(hash(raw))}", "run_id": run_id, "command_id": command_id, "timestamp": utc_now(), "protocol": protocol, "host": host, "port": port, "finding_type": finding_type, "severity": "Info", "confidence": "medium", "redacted_evidence": raw, "raw_reference": str(stdout_path), "metadata": attrs})
        if "signing:false" in raw.lower() or "signing: false" in raw.lower():
            append_jsonl(out / "jsonl/findings.jsonl", {"finding_id": f"{command_id}-signing-{host}", "run_id": run_id, "command_id": command_id, "timestamp": utc_now(), "protocol": protocol, "host": host, "port": port, "finding_type": "smb_signing_disabled", "severity": "Medium", "confidence": "medium", "redacted_evidence": raw, "raw_reference": str(stdout_path), "metadata": attrs})
        append_jsonl(out / "jsonl/events.jsonl", {"event_id": f"{command_id}-{abs(hash(raw))}", "command_id": command_id, "run_id": run_id, "timestamp": utc_now(), "source": "nxc", "protocol": protocol, "host": host, "port": port, "hostname": "", "domain": "", "os": "", "normalized_message": msg, "raw_redacted_line": raw, "attributes": attrs})


def main() -> int:
    os.umask(0o077)
    args = parse_args()
    out = Path(args.out)
    mkdirs(out)
    selected_modules = [x.strip() for x in args.allow_modules.split(",") if x.strip()]
    safety_check(args, selected_modules)
    selected = [p.strip() for p in args.protocols.split(",") if p.strip()] or ALL_PROTOCOLS
    selected = [p for p in selected if p in ALL_PROTOCOLS]
    targets = read_targets(Path(args.targets), args.max_hosts)
    proto_targets = service_protocol_targets(Path(args.service_map), set(targets), selected)
    caps = capture_capabilities(out, selected)
    run_meta = {"run_id": args.run_id, "tool_name": "nxc", "script_name": Path(__file__).name, "start_timestamp": utc_now(), "authorization_status": args.authorized, "mode": args.mode, "workspace": args.workspace, "target_input": args.targets, "service_map_input": args.service_map, "selected_protocols": selected, "nxc_version": (out / "meta/nxc_version.txt").read_text(encoding="utf-8", errors="replace") if (out / "meta/nxc_version.txt").exists() else "", "safety_flags": {k: getattr(args, k) for k in vars(args) if k.startswith("allow_")}, "generic_options": generic_args(args)}
    write_json(out / "meta/run.json", run_meta)
    for proto, hosts in proto_targets.items():
        (out / "targets" / f"{proto}.txt").write_text("\n".join(hosts) + "\n", encoding="utf-8")
    (out / "targets/all.normalized.txt").write_text("\n".join(targets) + "\n", encoding="utf-8")
    if not shutil.which("nxc"):
        write_json(out / "json/summary.json", {"available": False, "error": "nxc not installed", "protocols": selected})
        return 0
    for proto, hosts in proto_targets.items():
        target_file = out / "targets" / f"{proto}.txt"
        command_id = f"nxc-{proto}-{int(time.time())}"
        stdout_path = out / "logs/raw" / f"{command_id}.stdout.txt"
        stderr_path = out / "logs/stderr" / f"{command_id}.stderr.txt"
        nxc_log = out / "logs/nxc" / f"{command_id}.log"
        cmd = ["nxc", *generic_args(args), proto, str(target_file), *auth_args(args), "--log", str(nxc_log)]
        started = time.time()
        rec = {"command_id": command_id, "run_id": args.run_id, "phase": "nxc", "protocol": proto, "task": args.mode, "start_timestamp": utc_now(), "redacted_argv": redact(cmd, args.redact_secrets), "target_file": str(target_file), "target_count": len(hosts), "stdout_path": str(stdout_path), "stderr_path": str(stderr_path), "nxc_log_path": str(nxc_log), "native_artifacts": [], "parse_status": "not_started", "error": ""}
        if args.dry_run:
            rec.update({"end_timestamp": utc_now(), "duration": 0, "exit_code": None, "parse_status": "dry_run"})
            append_jsonl(out / "jsonl/commands.jsonl", rec)
            continue
        rc, stdout, stderr = run_capture(cmd, max(30, len(hosts) * (args.timeout + 15)))
        stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
        stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
        rec.update({"end_timestamp": utc_now(), "duration": round(time.time() - started, 3), "exit_code": rc})
        try:
            parse_output(proto, command_id, args.run_id, stdout_path, out)
            rec["parse_status"] = "parsed"
        except Exception as exc:
            rec["parse_status"] = "failed"
            rec["error"] = str(exc)
            append_jsonl(out / "jsonl/events.jsonl", {"event_id": f"{command_id}-parse-failed", "command_id": command_id, "run_id": args.run_id, "timestamp": utc_now(), "source": "parser", "protocol": proto, "host": "", "port": None, "hostname": "", "domain": "", "os": "", "normalized_message": "parse failure", "raw_redacted_line": "", "attributes": {"error": str(exc)}})
        append_jsonl(out / "jsonl/commands.jsonl", rec)
    findings = []
    if (out / "jsonl/findings.jsonl").exists():
        findings = [json.loads(line) for line in (out / "jsonl/findings.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    events = []
    if (out / "jsonl/events.jsonl").exists():
        events = [json.loads(line) for line in (out / "jsonl/events.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    write_json(out / "json/summary.json", {"available": True, "protocols": selected, "protocol_targets": proto_targets, "event_count": len(events), "finding_count": len(findings)})
    for name in ["hosts", "services", "auth_successes", "admin_rights", "shares", "nfs_exports", "mssql", "ldap", "modules"]:
        write_json(out / "json" / f"{name}.json", [] if name != "modules" else {"capabilities": caps})
    (out / "reports/markdown-summary.md").write_text(f"# NXC Summary\n\nProtocols: {', '.join(selected)}\n\nFindings: {len(findings)}\n", encoding="utf-8")
    run_meta["end_timestamp"] = utc_now()
    write_json(out / "meta/run.json", run_meta)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
