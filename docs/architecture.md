# C3PO Local Scanner Architecture

## Overview

C3PO Local is an interface-scoped internal network scanner. It is self-contained and does not depend on external MCP servers, Shodan, Docker PoC targets, public attack-surface workflows, or repository agent/skill files.

## Components

- `run.sh`: thin root entrypoint.
- `bin/run.sh`: startup UX, authorization banner, dynamic Codex selection, and Python scanner invocation.
- `pipeline/codex_catalog.py`: one-shot structured catalog loading, validation, and interactive selection.
- `pipeline/local_scanner.py`: scope derivation, discovery, Nmap/Nuclei orchestration, top-host prioritization, Codex interpretation fallback, artifact writing, and HTML reporting.
- `tools/nxc_phase.py`: standalone safe NetExec/NXC wrapper with protocol targeting, capability snapshots, safety gates, raw logs, JSONL events/findings, and summary JSON.
- `scripts/validate.sh`: lightweight local dependency and repository sanity checks.

## Runtime Model

Each run writes to `runs/YYYYmmdd-HHMMSS/`. Raw command output, structured JSON, JSONL command records, and the final HTML report stay together for reproducibility.

External commands are wrapped so each phase records command argv, redacted argv, start/end time, duration, exit code, timeout state, stdout path, stderr path, and errors.

## Scope Model

The scanner reads local interface and route state with:

- `ip -j link show dev <interface>`
- `ip -j addr show dev <interface>`
- `ip route show dev <interface>`
- `ip neigh show dev <interface>`

Only private IPv4 scope derived from the selected interface is eligible. Default routes, public ranges, loopback, link-local active sweeps, multicast, broadcast, documentation ranges, overly broad active ranges, and unrelated routes are excluded.

## Scan Stages

1. Tool version capture.
2. Scope derivation into `scope.json` and `scope.txt`.
3. Live host discovery into `live-hosts.txt` and `live-hosts.json`.
4. Fast Nmap against live hosts only with a bounded infrastructure port set.
5. Top-host scoring and optional Codex interpretation.
6. Deep Nmap only against selected top hosts.
7. Nuclei only against top-host HTTP/HTTPS services.
8. NXC only against protocols indicated by observed services.
9. Final report generation.

## Prioritization

Risk scoring uses local evidence: gateway/router indicators, `192.168.100.1` FritzBox/router status, DNS/identity/storage/admin/database/web exposure, legacy protocols, service count, and local tool findings. Open ports are treated as exposure, not vulnerability proof.

## NXC Safety

The NXC wrapper defaults to no-auth recon. It refuses active execution without `--authorized`, uses target files and service maps only, does not discover new ranges, rejects credential spraying unless explicitly allowed, and blocks command execution, secret dumping, file transfer, coercion, BloodHound, ADCS abuse, and password changes unless matching dangerous allow flags are supplied.
